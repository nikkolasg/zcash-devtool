//! Thin async client for the simplex-chat CLI WebSocket JSON API.
//!
//! Protocol: requests are `{"corrId": "<unique>", "cmd": "<command>"}`; the matching
//! response arrives as `{"corrId": "<same>", "resp": {...}}`. Asynchronous events are
//! delivered as objects with a `resp` field and no (or an empty) `corrId`. The exact
//! JSON shapes vary between simplex-chat versions, so mismatching events are logged at
//! debug level and skipped rather than treated as errors.

use std::collections::VecDeque;
use std::time::Duration;

use anyhow::{Context, anyhow};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
use tracing::{debug, info};

/// Deadline for a single command round-trip (and the initial connect). The
/// daemon answers locally in milliseconds; anything slower means it is wedged,
/// and without a deadline `advice send`/`pair` would hang forever.
const CMD_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct SimplexClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    /// Events received while waiting for a command response.
    events: VecDeque<Value>,
    /// Direct-message texts from a single `newChatItems` event that carried
    /// more than one (simplex-chat batches messages queued while the client
    /// was offline — the `advice flush` reconnect case). `(contact, text)`
    /// pairs are drained before reading the socket so none is dropped.
    pending_texts: VecDeque<(String, String)>,
    next_corr_id: u64,
}

impl SimplexClient {
    pub(crate) async fn connect(ws_url: &str) -> anyhow::Result<Self> {
        info!("Connecting to simplex-chat at {}", ws_url);
        let (ws, _) = tokio::time::timeout(CMD_TIMEOUT, connect_async(ws_url))
            .await
            .map_err(|_| anyhow!("timed out connecting to simplex-chat at {ws_url}"))?
            .with_context(|| format!("failed to connect to simplex-chat WebSocket at {ws_url}"))?;
        Ok(Self {
            ws,
            events: VecDeque::new(),
            pending_texts: VecDeque::new(),
            next_corr_id: 0,
        })
    }

    async fn read_json(&mut self) -> anyhow::Result<Value> {
        loop {
            let msg = self
                .ws
                .next()
                .await
                .ok_or_else(|| anyhow!("simplex-chat WebSocket closed"))??;
            match msg {
                Message::Text(text) => match serde_json::from_str::<Value>(&text) {
                    Ok(value) => return Ok(value),
                    Err(e) => debug!("Ignoring non-JSON simplex frame ({e}): {text}"),
                },
                other => debug!("Ignoring non-text simplex frame: {other:?}"),
            }
        }
    }

    /// Sends a command and waits (bounded by [`CMD_TIMEOUT`]) for the response
    /// carrying the same corrId. Events received in the meantime are queued for
    /// `next_event` so they are not lost. An Either-style `{"Left": ...}` response
    /// is a command error and is returned as `Err`.
    pub(crate) async fn send_cmd(&mut self, cmd: &str) -> anyhow::Result<Value> {
        self.next_corr_id += 1;
        let corr_id = format!("devtool-{}", self.next_corr_id);
        let frame = json!({ "corrId": corr_id, "cmd": cmd }).to_string();
        debug!("simplex >> {}", frame);
        self.ws.send(Message::Text(frame.into())).await?;

        tokio::time::timeout(CMD_TIMEOUT, async {
            loop {
                let value = self.read_json().await?;
                if value.get("corrId").and_then(Value::as_str) == Some(corr_id.as_str()) {
                    let resp = value.get("resp").cloned().ok_or_else(|| {
                        anyhow!("simplex-chat response has no `resp` field: {value}")
                    })?;
                    debug!("simplex << {}", resp);
                    return unwrap_either(resp)
                        .map_err(|e| anyhow!("simplex-chat command `{cmd}` failed: {e}"));
                }
                debug!("Queueing simplex event while awaiting response: {}", value);
                self.events.push_back(value);
            }
        })
        .await
        .map_err(|_| anyhow!("timed out after {CMD_TIMEOUT:?} waiting for response to `{cmd}`"))?
    }

    /// Returns the next asynchronous event payload (the contents of its `resp`
    /// field). Error-arm (`Left`) events are logged and skipped: they concern
    /// whatever operation failed, not the event stream itself.
    pub(crate) async fn next_event(&mut self) -> anyhow::Result<Value> {
        loop {
            let value = match self.events.pop_front() {
                Some(v) => v,
                None => self.read_json().await?,
            };
            match value.get("resp") {
                Some(resp) => match unwrap_either(resp.clone()) {
                    Ok(event) => return Ok(event),
                    Err(e) => debug!("Skipping error event: {e}"),
                },
                None => debug!("Ignoring simplex frame without `resp`: {}", value),
            }
        }
    }

    /// Creates a connection invitation and returns the invitation link.
    pub(crate) async fn create_invitation(&mut self) -> anyhow::Result<String> {
        let resp = self.send_cmd("/connect").await?;
        find_invitation_link(&resp)
            .ok_or_else(|| anyhow!("no invitation link found in simplex-chat response: {resp}"))
    }

    /// Joins a connection from an invitation link.
    pub(crate) async fn join(&mut self, link: &str) -> anyhow::Result<()> {
        let resp = self.send_cmd(&format!("/connect {link}")).await?;
        if resp.get("type").and_then(Value::as_str) == Some("chatCmdError") {
            return Err(anyhow!("simplex-chat failed to join invitation: {resp}"));
        }
        Ok(())
    }

    /// Sends a text message to a contact by display name.
    pub(crate) async fn send_text(&mut self, display_name: &str, text: &str) -> anyhow::Result<()> {
        // Display names are peer-influenced; one containing a quote would
        // break out of the CLI command quoting below and misroute the text.
        if display_name.contains('\'') {
            return Err(anyhow!(
                "refusing to message contact with unsupported display name {display_name:?}"
            ));
        }
        let cmd = if display_name.chars().any(char::is_whitespace) {
            format!("@'{display_name}' {text}")
        } else {
            format!("@{display_name} {text}")
        };
        let resp = self.send_cmd(&cmd).await?;
        if resp.get("type").and_then(Value::as_str) == Some("chatCmdError") {
            return Err(anyhow!("simplex-chat failed to send message: {resp}"));
        }
        Ok(())
    }

    /// Waits for a `contactConnected` event and returns the contact's display name.
    pub(crate) async fn wait_contact_connected(
        &mut self,
        timeout: Duration,
    ) -> anyhow::Result<String> {
        tokio::time::timeout(timeout, async {
            loop {
                let event = self.next_event().await?;
                if event.get("type").and_then(Value::as_str) == Some("contactConnected") {
                    if let Some(name) = find_string_by_key(&event, "localDisplayName") {
                        return Ok(name);
                    }
                    debug!("contactConnected event without a display name: {}", event);
                } else {
                    debug!("Skipping simplex event: {}", event);
                }
            }
        })
        .await
        .map_err(|_| anyhow!("timed out after {timeout:?} waiting for contactConnected"))?
    }

    /// Waits for a direct text message from the given contact and returns its
    /// text. A `newChatItems` event may carry several messages (batched
    /// offline delivery); all of theirs are buffered so a later call returns
    /// them instead of dropping all but the first.
    pub(crate) async fn wait_text_from(
        &mut self,
        contact: &str,
        timeout: Duration,
    ) -> anyhow::Result<String> {
        tokio::time::timeout(timeout, async {
            loop {
                // Serve any buffered text from a prior batched event first.
                while let Some((from, text)) = self.pending_texts.pop_front() {
                    if from == contact {
                        return Ok(text);
                    }
                    debug!("Dropping buffered text from {from} while waiting for {contact}");
                }
                let event = self.next_event().await?;
                if event.get("type").and_then(Value::as_str) != Some("newChatItems") {
                    debug!("Skipping simplex event: {}", event);
                    continue;
                }
                let mut texts = extract_direct_texts(&event);
                if texts.is_empty() {
                    debug!(
                        "newChatItems event without a direct text message: {}",
                        event
                    );
                    continue;
                }
                // Return the first match for `contact`; buffer the rest (both
                // this contact's extra messages and other contacts').
                let mut found = None;
                for (from, text) in texts.drain(..) {
                    if found.is_none() && from == contact {
                        found = Some(text);
                    } else {
                        self.pending_texts.push_back((from, text));
                    }
                }
                match found {
                    Some(text) => return Ok(text),
                    None => debug!("newChatItems event had no message from {contact}"),
                }
            }
        })
        .await
        .map_err(|_| anyhow!("timed out after {timeout:?} waiting for a message from {contact}"))?
    }
}

/// Some simplex-chat versions wrap `resp` payloads in an Either-style
/// `{"Right": {...}}` / `{"Left": {...}}` object. `Right` unwraps to the
/// payload; `Left` is the error arm and becomes an `Err` regardless of the
/// inner `type`, so a failed command can never pass as success.
fn unwrap_either(resp: Value) -> anyhow::Result<Value> {
    if let Some(obj) = resp.as_object() {
        if obj.len() == 1 {
            if let Some(inner) = obj.get("Right") {
                return Ok(inner.clone());
            }
            if let Some(inner) = obj.get("Left") {
                return Err(anyhow!("{inner}"));
            }
        }
    }
    Ok(resp)
}

/// Recursively searches a JSON value for the first string containing "/invitation#".
fn find_invitation_link(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if s.contains("/invitation#") => Some(s.clone()),
        Value::Array(items) => items.iter().find_map(find_invitation_link),
        Value::Object(map) => map.values().find_map(find_invitation_link),
        _ => None,
    }
}

/// Recursively searches a JSON value for the first string value under the given key.
fn find_string_by_key(value: &Value, key: &str) -> Option<String> {
    match value {
        Value::Array(items) => items.iter().find_map(|v| find_string_by_key(v, key)),
        Value::Object(map) => map
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| map.values().find_map(|v| find_string_by_key(v, key))),
        _ => None,
    }
}

/// Extracts every direct text message from a `newChatItems` event as
/// `(sender display name, text)` pairs, in order. A single event can batch
/// several messages (offline delivery on reconnect), so all are returned.
fn extract_direct_texts(event: &Value) -> Vec<(String, String)> {
    let Some(items) = event.get("chatItems").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let chat_info = item.get("chatInfo")?;
            if chat_info.get("type").and_then(Value::as_str) != Some("direct") {
                return None;
            }
            let name = chat_info
                .get("contact")?
                .get("localDisplayName")?
                .as_str()?;
            let text = item
                .get("chatItem")?
                .get("content")?
                .get("msgContent")?
                .get("text")?
                .as_str()?;
            Some((name.to_owned(), text.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{extract_direct_texts, find_invitation_link, unwrap_either};

    #[test]
    fn finds_invitation_link_at_any_depth() {
        let resp = json!({
            "type": "invitation",
            "connLinkInvitation": {
                "connFullLink": "https://simplex.chat/invitation#/?v=2&smp=xyz"
            }
        });
        assert_eq!(
            find_invitation_link(&resp).as_deref(),
            Some("https://simplex.chat/invitation#/?v=2&smp=xyz")
        );
        assert_eq!(find_invitation_link(&json!({"type": "ok"})), None);
    }

    #[test]
    fn unwraps_either_style_responses() {
        let wrapped = json!({"Right": {"type": "ok"}});
        assert_eq!(unwrap_either(wrapped).unwrap(), json!({"type": "ok"}));
        let plain = json!({"type": "ok", "extra": 1});
        assert_eq!(unwrap_either(plain.clone()).unwrap(), plain);
        let error_arm = json!({"Left": {"type": "error", "reason": "nope"}});
        assert!(unwrap_either(error_arm).is_err());
    }

    #[test]
    fn extracts_all_direct_texts_in_a_batched_event() {
        let item = |name: &str, text: &str| {
            json!({
                "chatInfo": { "type": "direct", "contact": { "localDisplayName": name } },
                "chatItem": { "content": { "msgContent": { "type": "text", "text": text } } }
            })
        };
        // A single event batching three messages (offline delivery): all are
        // returned, in order, so none is dropped.
        let event = json!({
            "type": "newChatItems",
            "chatItems": [item("alice", "one"), item("bob", "two"), item("alice", "three")]
        });
        assert_eq!(
            extract_direct_texts(&event),
            vec![
                ("alice".to_owned(), "one".to_owned()),
                ("bob".to_owned(), "two".to_owned()),
                ("alice".to_owned(), "three".to_owned()),
            ]
        );
        assert!(extract_direct_texts(&json!({"type": "newChatItems"})).is_empty());
    }
}

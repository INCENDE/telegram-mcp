//! Model Context Protocol framing: JSON-RPC 2.0 over a single HTTP POST per
//! message (the "streamable HTTP" transport, used statelessly). Tool
//! execution lives in `account.rs`; this module only knows the envelope and
//! the tool catalogue.

use serde_json::{json, Value};

pub const PROTOCOL_VERSION: &str = "2025-06-18";

pub enum Incoming {
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Notification,
    Invalid(String),
}

pub fn parse(body: &str) -> Incoming {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return Incoming::Invalid(format!("parse error: {e}")),
    };
    if !v.is_object() {
        return Incoming::Invalid("batch requests are not supported".into());
    }
    let method = match v.get("method").and_then(Value::as_str) {
        Some(m) => m.to_string(),
        None => return Incoming::Invalid("missing method".into()),
    };
    match v.get("id") {
        None | Some(Value::Null) => Incoming::Notification,
        Some(id) => Incoming::Request {
            id: id.clone(),
            method,
            params: v.get("params").cloned().unwrap_or(Value::Null),
        },
    }
}

pub fn ok(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

pub fn error(id: &Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INVALID_REQUEST: i64 = -32600;

pub fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": {
            "name": "telegram-mcp",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": "Telegram, as the account owner. Chat ids come from list_chats. \
            Messages are returned oldest first. send_message only works for chats the \
            server was configured to allow; everything else is read-only.",
    })
}

/// A tool call's result: text content, optionally flagged as an error.
pub fn tool_result(text: String, is_error: bool) -> Value {
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error,
    })
}

pub fn tools() -> Value {
    json!({ "tools": [
        {
            "name": "list_chats",
            "description": "List recent chats (users, groups, channels) with their ids and unread counts, most recent first.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 30 }
                }
            }
        },
        {
            "name": "get_messages",
            "description": "Read messages from one chat, oldest first. Use before_id to page further back.",
            "inputSchema": {
                "type": "object",
                "required": ["chat_id"],
                "properties": {
                    "chat_id": { "type": "integer", "description": "An id from list_chats" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 30 },
                    "before_id": { "type": "integer", "description": "Only messages older than this message id" }
                }
            }
        },
        {
            "name": "search_messages",
            "description": "Search message text, in one chat or across all chats.",
            "inputSchema": {
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": { "type": "string" },
                    "chat_id": { "type": "integer", "description": "Restrict to this chat; omit to search everywhere" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 }
                }
            }
        },
        {
            "name": "send_message",
            "description": "Send a plain-text message to a chat. Only chats on the server's allow-list accept sends.",
            "inputSchema": {
                "type": "object",
                "required": ["chat_id", "text"],
                "properties": {
                    "chat_id": { "type": "integer" },
                    "text": { "type": "string" },
                    "reply_to": { "type": "integer", "description": "Message id to reply to" }
                }
            }
        }
    ]})
}

/// Read an integer argument with bounds and a default.
pub fn int_arg(args: &Value, name: &str, default: i64) -> std::result::Result<i64, String> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => v
            .as_i64()
            .or_else(|| v.as_f64().map(|f| f as i64))
            .ok_or_else(|| format!("'{name}' must be an integer")),
    }
}

pub fn opt_int_arg(args: &Value, name: &str) -> std::result::Result<Option<i64>, String> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .or_else(|| v.as_f64().map(|f| f as i64))
            .map(Some)
            .ok_or_else(|| format!("'{name}' must be an integer")),
    }
}

pub fn str_arg<'a>(args: &'a Value, name: &str) -> std::result::Result<&'a str, String> {
    args.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("'{name}' is required"))
}

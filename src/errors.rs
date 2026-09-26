//! Error types and the user-facing error formatter shared by every tool.

use std::fmt;

use grammers_client::InvocationError;

/// A startup configuration problem; printed and turned into exit code 1.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

/// A validation problem in tool arguments. Its message is returned verbatim.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct ValidationError(pub String);

/// Access to a chat is restricted by `TELEGRAM_ALLOWED_CHAT_IDS`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct ChatAccessDenied(pub String);

/// Carries an agent-facing JSON instruction to ask the human which contact is
/// meant. Not a failure: returned verbatim and never logged at error level.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{payload}")]
pub struct AliasNeedsUser {
    pub payload: String,
}

/// Convenience alias for tool bodies.
pub type ToolResult<T> = Result<T, anyhow::Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Chat,
    Msg,
    Contact,
    Group,
    Media,
    Profile,
    Auth,
    Admin,
    Folder,
    Privacy,
}

impl ErrorCategory {
    const ALL: [ErrorCategory; 10] = [
        Self::Chat,
        Self::Msg,
        Self::Contact,
        Self::Group,
        Self::Media,
        Self::Profile,
        Self::Auth,
        Self::Admin,
        Self::Folder,
        Self::Privacy,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "CHAT",
            Self::Msg => "MSG",
            Self::Contact => "CONTACT",
            Self::Group => "GROUP",
            Self::Media => "MEDIA",
            Self::Profile => "PROFILE",
            Self::Auth => "AUTH",
            Self::Admin => "ADMIN",
            Self::Folder => "FOLDER",
            Self::Privacy => "PRIVACY",
        }
    }

    fn derive(function_name: &str) -> Option<Self> {
        let lower = function_name.to_ascii_lowercase();
        Self::ALL
            .iter()
            .copied()
            .find(|c| lower.contains(&c.as_str().to_ascii_lowercase()))
    }
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable three-digit code for a function name (FNV-1a, unlike Python's
/// per-process randomised `hash`).
pub fn function_code(function_name: &str) -> u32 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in function_name.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash % 1000) as u32
}

/// Seconds Telegram asked us to wait, when `error` is a flood wait.
pub fn flood_wait_seconds(error: &anyhow::Error) -> Option<u32> {
    let inv = error.downcast_ref::<InvocationError>()?;
    rpc_flood_wait(inv)
}

pub fn rpc_flood_wait(error: &InvocationError) -> Option<u32> {
    match error {
        InvocationError::Rpc(rpc)
            if rpc.name == "FLOOD_WAIT" || rpc.name == "FLOOD_PREMIUM_WAIT" =>
        {
            Some(rpc.value.unwrap_or(0))
        }
        _ => None,
    }
}

/// True when the server sent a constructor this build's TL schema does not know.
pub fn is_schema_drift(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<InvocationError>(),
        Some(InvocationError::Deserialize(_))
    )
}

/// True when an RPC error names a specific Telegram error (supports `*` suffix).
pub fn rpc_is(error: &anyhow::Error, name: &str) -> bool {
    match error.downcast_ref::<InvocationError>() {
        Some(InvocationError::Rpc(rpc)) => rpc.is(name),
        _ => false,
    }
}

pub fn rpc_name(error: &anyhow::Error) -> Option<&str> {
    match error.downcast_ref::<InvocationError>() {
        Some(InvocationError::Rpc(rpc)) => Some(rpc.name.as_str()),
        _ => None,
    }
}

/// True when Telegram rejected a call because the account lacks Premium.
pub fn is_premium_rpc_error(error: &anyhow::Error) -> bool {
    error.to_string().to_ascii_uppercase().contains("PREMIUM")
}

/// Centralised error formatter. Logs a categorical record (never exception
/// text, identifiers or user content) and returns the user-facing message.
pub fn log_and_format_error(
    function_name: &str,
    error: &anyhow::Error,
    prefix: Option<&str>,
    user_message: Option<&str>,
) -> String {
    if let Some(ask) = error.downcast_ref::<AliasNeedsUser>() {
        return ask.payload.clone();
    }
    let error_code = if prefix == Some("VALIDATION-001") {
        "VALIDATION-001".to_string()
    } else {
        let prefix_str = match prefix {
            Some(p) => p.to_string(),
            None => ErrorCategory::derive(function_name)
                .map(|c| c.as_str().to_string())
                .unwrap_or_else(|| "GEN".to_string()),
        };
        format!("{prefix_str}-ERR-{:03}", function_code(function_name))
    };

    if let Some(seconds) = flood_wait_seconds(error) {
        log::warn!("Telegram FloodWait; retry only after the reported delay.");
        if let Some(msg) = user_message {
            return msg.to_string();
        }
        let wait_clause = if seconds > 0 {
            format!("{seconds} seconds")
        } else {
            "an unknown duration".to_string()
        };
        return format!(
            "Rate limit exceeded (FloodWait): Telegram requires waiting {wait_clause} before repeating this operation. Do NOT retry immediately (code: {error_code})."
        );
    }

    log::error!("Telegram MCP operation failed; see the returned stable error code.");
    log::debug!("{function_name}: {error:#}");

    if let Some(msg) = user_message {
        return msg.to_string();
    }
    if is_schema_drift(error) {
        return format!(
            "MTProto schema mismatch: this build does not know an object the server sent. This is NOT a missing user or chat; the data arrived, parsing it failed. Upgrade telegram-mcp (code: {error_code})."
        );
    }
    format!("An error occurred (code: {error_code}).")
}

/// Shorthand for the common `except Exception as e: return log_and_format_error(...)` shape.
pub fn format_error(function_name: &str, error: &anyhow::Error) -> String {
    log_and_format_error(function_name, error, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_and_categorised() {
        let e = anyhow::anyhow!("boom");
        let a = format_error("get_chat", &e);
        assert!(a.starts_with("An error occurred (code: CHAT-ERR-"));
        assert_eq!(a, format_error("get_chat", &e));
        assert!(format_error("something", &e).contains("GEN-ERR-"));
    }

    #[test]
    fn validation_and_alias_passthrough() {
        let e = anyhow::Error::new(ValidationError("bad".into()));
        assert_eq!(
            log_and_format_error("f", &e, Some("VALIDATION-001"), Some("bad")),
            "bad"
        );
        let ask = anyhow::Error::new(AliasNeedsUser {
            payload: "{}".into(),
        });
        assert_eq!(format_error("f", &ask), "{}");
    }

    #[test]
    fn flood_wait_message() {
        let rpc = grammers_mtsender::RpcError {
            code: 420,
            name: "FLOOD_WAIT".into(),
            value: Some(30),
            caused_by: None,
        };
        let e = anyhow::Error::new(InvocationError::Rpc(rpc));
        let m = format_error("send_message", &e);
        assert!(m.contains("waiting 30 seconds"));
        assert!(m.contains("GEN-ERR-"));
    }
}

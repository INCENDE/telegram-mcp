//! Environment-driven configuration, parsed once at startup and failing
//! loudly on malformed values.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::errors::ConfigError;

pub const TOOL_TIMEOUT_SECONDS_DEFAULT: f64 = 55.0;
pub const ROOTS_REQUEST_TIMEOUT_DEFAULT: f64 = 10.0;

pub fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

pub fn parse_bool(value: Option<&str>, default: bool) -> bool {
    match value {
        None => default,
        Some(v) => {
            let v = v.trim().to_ascii_lowercase();
            if v.is_empty() {
                default
            } else {
                matches!(v.as_str(), "1" | "true" | "yes" | "on")
            }
        }
    }
}

pub fn bool_env(name: &str, default: bool) -> bool {
    parse_bool(std::env::var(name).ok().as_deref(), default)
}

/// Server-side ceiling for one MCP tool call. `None` means unbounded.
pub fn tool_timeout(value: Option<&str>) -> Option<Duration> {
    let raw = match value {
        Some(v) => Some(v.to_string()),
        None => env("TELEGRAM_TOOL_TIMEOUT_SECONDS"),
    };
    match raw {
        None => Some(Duration::from_secs_f64(TOOL_TIMEOUT_SECONDS_DEFAULT)),
        Some(v) => match v.trim().parse::<f64>() {
            Ok(t) if t > 0.0 => Some(Duration::from_secs_f64(t)),
            Ok(_) => None,
            Err(_) => Some(Duration::from_secs_f64(TOOL_TIMEOUT_SECONDS_DEFAULT)),
        },
    }
}

/// Seconds to wait for the client's roots/list reply. `None` waits forever.
pub fn roots_timeout(value: Option<&str>) -> Option<Duration> {
    let raw = match value {
        Some(v) => Some(v.to_string()),
        None => env("TELEGRAM_ROOTS_TIMEOUT_SECONDS"),
    };
    match raw {
        None => Some(Duration::from_secs_f64(ROOTS_REQUEST_TIMEOUT_DEFAULT)),
        Some(v) if v.trim().is_empty() => {
            Some(Duration::from_secs_f64(ROOTS_REQUEST_TIMEOUT_DEFAULT))
        }
        Some(v) => match v.trim().parse::<f64>() {
            Ok(t) if t > 0.0 => Some(Duration::from_secs_f64(t)),
            Ok(_) => None,
            Err(_) => Some(Duration::from_secs_f64(ROOTS_REQUEST_TIMEOUT_DEFAULT)),
        },
    }
}

pub fn server_roots_fallback_enabled(value: Option<&str>) -> bool {
    match value {
        Some(v) => parse_bool(Some(v), false),
        None => bool_env("TELEGRAM_ALLOW_SERVER_ROOTS_FALLBACK", false),
    }
}

/// Seconds below which flood waits are slept through automatically.
pub fn flood_sleep_threshold() -> u64 {
    env("TELEGRAM_FLOOD_SLEEP_THRESHOLD")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(60)
}

// ---------------------------------------------------------------------------
// Tool exposure mode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExposedTools {
    All,
    ReadOnly { allow: Vec<String> },
}

pub fn parse_exposed_tools(raw: &str) -> Result<ExposedTools, ConfigError> {
    let mode = raw.trim().to_ascii_lowercase();
    let (base, allow) = match mode.split_once('+') {
        None => (mode.as_str(), None),
        Some((b, a)) => (b, Some(a)),
    };
    if base != "all" && base != "read-only" {
        return Err(ConfigError(format!(
            "Invalid TELEGRAM_EXPOSED_TOOLS '{raw}'. Expected one of: all, read-only."
        )));
    }
    match allow {
        None => Ok(if base == "all" {
            ExposedTools::All
        } else {
            ExposedTools::ReadOnly { allow: vec![] }
        }),
        Some(list) => {
            if base != "read-only" {
                return Err(ConfigError(format!(
                    "Invalid TELEGRAM_EXPOSED_TOOLS '{raw}'. The '+tool,tool' allowlist is only valid with read-only."
                )));
            }
            let names: Vec<String> = list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if names.is_empty() {
                return Err(ConfigError(format!(
                    "Invalid TELEGRAM_EXPOSED_TOOLS '{raw}'. The '+' allowlist must name at least one tool."
                )));
            }
            Ok(ExposedTools::ReadOnly { allow: names })
        }
    }
}

pub fn exposed_tools_from_env() -> Result<ExposedTools, ConfigError> {
    parse_exposed_tools(&std::env::var("TELEGRAM_EXPOSED_TOOLS").unwrap_or_else(|_| "all".into()))
}

// ---------------------------------------------------------------------------
// Per-tool file extension allowlists
// ---------------------------------------------------------------------------

pub type ExtensionAllowlists = BTreeMap<String, BTreeSet<String>>;

pub fn default_extension_allowlists() -> ExtensionAllowlists {
    let mut m = ExtensionAllowlists::new();
    let set = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
    m.insert("send_voice".into(), set(&[".ogg", ".opus"]));
    m.insert("send_sticker".into(), set(&[".webp"]));
    m.insert(
        "set_profile_photo".into(),
        set(&[".jpg", ".jpeg", ".png", ".webp"]),
    );
    m.insert(
        "edit_chat_photo".into(),
        set(&[".jpg", ".jpeg", ".png", ".webp"]),
    );
    m
}

pub fn max_file_bytes(tool: &str) -> Option<u64> {
    const MB: u64 = 1024 * 1024;
    match tool {
        "download_media" | "send_file" | "upload_file" => Some(200 * MB),
        "send_voice" => Some(100 * MB),
        "send_sticker" => Some(10 * MB),
        "set_profile_photo" | "edit_chat_photo" => Some(50 * MB),
        _ => None,
    }
}

fn valid_extension_token(token: &str) -> bool {
    let rest = match token.strip_prefix('.') {
        Some(r) => r,
        None => return false,
    };
    !rest.is_empty()
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Parse `TELEGRAM_FILE_EXTENSIONS=tool:.ext,.ext;tool2:.ext`.
pub fn parse_extension_overrides(raw: &str) -> Result<ExtensionAllowlists, ConfigError> {
    let raw_trim = raw.trim();
    let mut out = ExtensionAllowlists::new();
    if raw_trim.is_empty() {
        return Ok(out);
    }
    for entry in raw_trim.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (tool, exts) = match entry.split_once(':') {
            Some((t, e)) if !t.trim().is_empty() => (t.trim().to_ascii_lowercase(), e),
            _ => {
                return Err(ConfigError(format!(
                    "Invalid TELEGRAM_FILE_EXTENSIONS '{raw}'. Each entry must look like 'tool:.ext,.ext', entries separated by ';'."
                )))
            }
        };
        let mut set = BTreeSet::new();
        for raw_ext in exts.split(',') {
            let mut token = raw_ext.trim().to_ascii_lowercase();
            if token.is_empty() {
                return Err(ConfigError(format!(
                    "Invalid TELEGRAM_FILE_EXTENSIONS '{raw}'. Tool '{tool}' has an empty extension entry."
                )));
            }
            if !token.starts_with('.') {
                token = format!(".{token}");
            }
            if !valid_extension_token(&token) {
                return Err(ConfigError(format!(
                    "Invalid TELEGRAM_FILE_EXTENSIONS '{raw}'. Malformed extension '{}' for tool '{tool}'.",
                    raw_ext.trim()
                )));
            }
            set.insert(token);
        }
        if out.contains_key(&tool) {
            return Err(ConfigError(format!(
                "Invalid TELEGRAM_FILE_EXTENSIONS '{raw}'. Tool '{tool}' is named more than once."
            )));
        }
        out.insert(tool, set);
    }
    Ok(out)
}

/// Merge overrides over the defaults; a named tool replaces its whole set.
pub fn effective_extension_allowlists(overrides: ExtensionAllowlists) -> ExtensionAllowlists {
    let mut m = default_extension_allowlists();
    for (k, v) in overrides {
        m.insert(k, v);
    }
    m
}

// ---------------------------------------------------------------------------
// Chat allowlist
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChatAllowlist {
    pub ids: BTreeSet<i64>,
    pub handles: BTreeSet<String>,
}

impl ChatAllowlist {
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty() && self.handles.is_empty()
    }
}

/// Parse `TELEGRAM_ALLOWED_CHAT_IDS`; `None` means the allowlist is disabled.
pub fn parse_allowed_chat_ids(raw: Option<&str>) -> Option<ChatAllowlist> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let mut allow = ChatAllowlist::default();
    for token in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if let Ok(val) = token.parse::<i64>() {
            allow.ids.insert(val);
            let s = val.to_string();
            if let Some(rest) = s.strip_prefix("-100") {
                if !rest.is_empty() {
                    if let Ok(channel_id) = rest.parse::<i64>() {
                        allow.ids.insert(channel_id);
                    }
                }
            } else if val > 0 {
                allow.ids.insert(-1_000_000_000_000 - val);
                allow.ids.insert(-val);
            } else if val < 0 {
                allow.ids.insert(-val);
            }
        } else {
            let clean = token.trim_start_matches('@').trim().to_ascii_lowercase();
            if !clean.is_empty() {
                allow.handles.insert(clean);
            }
        }
    }
    if allow.is_empty() {
        None
    } else {
        Some(allow)
    }
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

pub fn proxy_env(name: &str, label: &str) -> Option<String> {
    let suffixed = format!("TELEGRAM_PROXY_{name}_{}", label.to_ascii_uppercase());
    env(&suffixed).or_else(|| env(&format!("TELEGRAM_PROXY_{name}")))
}

/// Build the SOCKS5 proxy URL for a label, or `None` when no proxy is set.
pub fn proxy_url_for_label(label: &str) -> Result<Option<String>, ConfigError> {
    let Some(kind) = proxy_env("TYPE", label) else {
        return Ok(None);
    };
    let kind = kind.trim().to_ascii_lowercase();
    match kind.as_str() {
        "socks5" => {}
        "socks4" | "http" | "mtproxy" => {
            return Err(ConfigError(format!(
                "TELEGRAM_PROXY_TYPE '{kind}' is not supported by this build. Only socks5 proxies are supported."
            )))
        }
        other => {
            return Err(ConfigError(format!(
                "Invalid TELEGRAM_PROXY_TYPE '{other}'. Expected socks5."
            )))
        }
    }
    let host = proxy_env("HOST", label).ok_or_else(|| {
        ConfigError("TELEGRAM_PROXY_HOST is required when TELEGRAM_PROXY_TYPE is set.".into())
    })?;
    let port = proxy_env("PORT", label).ok_or_else(|| {
        ConfigError("TELEGRAM_PROXY_PORT is required when TELEGRAM_PROXY_TYPE is set.".into())
    })?;
    let port: u16 = port
        .trim()
        .parse()
        .map_err(|_| ConfigError(format!("Invalid TELEGRAM_PROXY_PORT '{port}'.")))?;
    let mut url = String::from("socks5://");
    if let Some(user) = proxy_env("USERNAME", label) {
        url.push_str(
            &percent_encoding::utf8_percent_encode(&user, percent_encoding::NON_ALPHANUMERIC)
                .to_string(),
        );
        if let Some(pass) = proxy_env("PASSWORD", label) {
            url.push(':');
            url.push_str(
                &percent_encoding::utf8_percent_encode(&pass, percent_encoding::NON_ALPHANUMERIC)
                    .to_string(),
            );
        }
        url.push('@');
    }
    if host.contains(':') && !host.starts_with('[') {
        url.push_str(&format!("[{host}]"));
    } else {
        url.push_str(&host);
    }
    url.push_str(&format!(":{port}"));
    Ok(Some(url))
}

// ---------------------------------------------------------------------------
// Device identity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct DeviceIdentity {
    pub device_model: Option<String>,
    pub system_version: Option<String>,
    pub app_version: Option<String>,
}

pub fn device_identity() -> DeviceIdentity {
    DeviceIdentity {
        device_model: env("TELEGRAM_DEVICE_MODEL"),
        system_version: env("TELEGRAM_SYSTEM_VERSION"),
        app_version: env("TELEGRAM_APP_VERSION"),
    }
}

// ---------------------------------------------------------------------------
// Transcription
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscribeMode {
    Off,
    OnDemand,
    Auto,
}

pub fn parse_transcribe_mode(raw: &str) -> Result<TranscribeMode, ConfigError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(TranscribeMode::Off),
        "on-demand" => Ok(TranscribeMode::OnDemand),
        "auto" => Ok(TranscribeMode::Auto),
        other => Err(ConfigError(format!(
            "Invalid TELEGRAM_TRANSCRIBE '{other}'. Expected one of: auto, off, on-demand."
        ))),
    }
}

pub fn transcribe_mode() -> TranscribeMode {
    parse_transcribe_mode(
        &std::env::var("TELEGRAM_TRANSCRIBE").unwrap_or_else(|_| "on-demand".into()),
    )
    .unwrap_or(TranscribeMode::OnDemand)
}

/// Validate every startup toggle, returning the first error.
pub fn validate_startup_toggles() -> Result<(), ConfigError> {
    exposed_tools_from_env()?;
    parse_extension_overrides(&std::env::var("TELEGRAM_FILE_EXTENSIONS").unwrap_or_default())?;
    parse_transcribe_mode(
        &std::env::var("TELEGRAM_TRANSCRIBE").unwrap_or_else(|_| "on-demand".into()),
    )?;
    if let Some(engine) = env("TELEGRAM_TRANSCRIBE_ENGINE") {
        if engine.trim().to_ascii_lowercase() != "telegram" {
            return Err(ConfigError(format!(
                "Invalid TELEGRAM_TRANSCRIBE_ENGINE '{engine}'. Only the native 'telegram' engine is available; third-party transcription has been removed."
            )));
        }
    }
    let lock = std::env::var("TELEGRAM_SESSION_LOCK").unwrap_or_else(|_| "exclusive".into());
    if !matches!(
        lock.trim().to_ascii_lowercase().as_str(),
        "exclusive" | "shared"
    ) {
        return Err(ConfigError(format!(
            "Invalid TELEGRAM_SESSION_LOCK '{lock}'. Expected one of: exclusive, shared."
        )));
    }
    Ok(())
}

pub fn session_lock_shared() -> bool {
    std::env::var("TELEGRAM_SESSION_LOCK")
        .map(|v| v.trim().eq_ignore_ascii_case("shared"))
        .unwrap_or(false)
}

pub fn lock_grace_seconds() -> f64 {
    env("TELEGRAM_LOCK_GRACE_SECONDS")
        .and_then(|v| v.trim().parse::<f64>().ok())
        .unwrap_or(crate::singleton::DEFAULT_GRACE_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposed_tools_modes() {
        assert_eq!(parse_exposed_tools("all").unwrap(), ExposedTools::All);
        assert_eq!(
            parse_exposed_tools(" Read-Only ").unwrap(),
            ExposedTools::ReadOnly { allow: vec![] }
        );
        assert_eq!(
            parse_exposed_tools("read-only+send_message, reply_to_message").unwrap(),
            ExposedTools::ReadOnly {
                allow: vec!["send_message".into(), "reply_to_message".into()]
            }
        );
        assert!(parse_exposed_tools("write").is_err());
        assert!(parse_exposed_tools("all+send_message").is_err());
        assert!(parse_exposed_tools("read-only+").is_err());
    }

    #[test]
    fn extension_overrides() {
        let m = parse_extension_overrides("send_file:.pdf,PNG;upload_file:.pdf").unwrap();
        assert_eq!(
            m["send_file"],
            [".pdf", ".png"].iter().map(|s| s.to_string()).collect()
        );
        assert!(parse_extension_overrides("send_file").is_err());
        assert!(parse_extension_overrides("send_file:.pdf,").is_err());
        assert!(parse_extension_overrides("send_file:.p df").is_err());
        assert!(parse_extension_overrides("a:.x;a:.y").is_err());
        assert!(parse_extension_overrides("  ").unwrap().is_empty());
        let eff =
            effective_extension_allowlists(parse_extension_overrides("send_voice:.mp3").unwrap());
        assert_eq!(
            eff["send_voice"],
            [".mp3"].iter().map(|s| s.to_string()).collect()
        );
        assert!(eff.contains_key("send_sticker"));
    }

    #[test]
    fn allowed_chat_ids() {
        assert!(parse_allowed_chat_ids(None).is_none());
        assert!(parse_allowed_chat_ids(Some(" ")).is_none());
        let a = parse_allowed_chat_ids(Some("123,-100456,@Foo,-789")).unwrap();
        assert!(
            a.ids.contains(&123) && a.ids.contains(&-1_000_000_000_123) && a.ids.contains(&-123)
        );
        assert!(a.ids.contains(&-100456) && a.ids.contains(&456));
        assert!(a.ids.contains(&-789) && a.ids.contains(&789));
        assert!(a.handles.contains("foo"));
    }

    #[test]
    fn timeouts() {
        assert_eq!(tool_timeout(Some("")), Some(Duration::from_secs_f64(55.0)));
        assert_eq!(tool_timeout(Some("0")), None);
        assert_eq!(
            tool_timeout(Some("12.5")),
            Some(Duration::from_secs_f64(12.5))
        );
        assert_eq!(
            tool_timeout(Some("abc")),
            Some(Duration::from_secs_f64(55.0))
        );
        assert_eq!(roots_timeout(Some("-1")), None);
    }

    #[test]
    fn bools() {
        assert!(parse_bool(Some("1"), false));
        assert!(parse_bool(Some("TRUE"), false));
        assert!(!parse_bool(Some("no"), true));
        assert!(parse_bool(None, true));
    }
}

//! Sanitisation of user-controlled Telegram content before it enters a tool
//! result. Defence in depth behind the structural JSON boundary: control and
//! zero-width characters are stripped, newlines collapsed, long text truncated.

use unicode_general_category::{get_general_category, GeneralCategory};

pub const DEFAULT_MAX_LENGTH: usize = 4096;
pub const NAME_MAX_LENGTH: usize = 256;

fn is_invisible(ch: char) -> bool {
    matches!(
        ch,
        '\u{200b}'..='\u{200f}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
    )
}

fn is_control_like(ch: char) -> bool {
    matches!(
        get_general_category(ch),
        GeneralCategory::Control | GeneralCategory::Format
    )
}

fn is_emoji_tag(ch: char) -> bool {
    ('\u{e0020}'..='\u{e007f}').contains(&ch)
}

/// Sanitise free text. Returns "[empty]" for empty input. Counts characters
/// (not bytes) for the truncation limit, matching the previous implementation.
pub fn sanitize_user_content_opts(
    text: Option<&str>,
    max_length: usize,
    preserve_emoji: bool,
) -> String {
    let text = match text {
        Some(t) if !t.is_empty() => t,
        _ => return "[empty]".to_string(),
    };
    let mut cleaned = String::with_capacity(text.len());
    for ch in text.chars() {
        if is_control_like(ch) {
            if ch == '\n' || ch == '\t' {
                cleaned.push(ch);
            } else if preserve_emoji && (ch == '\u{200d}' || is_emoji_tag(ch)) {
                cleaned.push(ch);
            }
            continue;
        }
        if is_invisible(ch) && !(preserve_emoji && ch == '\u{200d}') {
            continue;
        }
        cleaned.push(ch);
    }
    // Collapse three or more consecutive newlines to two.
    let mut collapsed = String::with_capacity(cleaned.len());
    let mut run = 0usize;
    for ch in cleaned.chars() {
        if ch == '\n' {
            run += 1;
            if run <= 2 {
                collapsed.push(ch);
            }
        } else {
            run = 0;
            collapsed.push(ch);
        }
    }
    let trimmed = collapsed.trim();
    if trimmed.is_empty() {
        return "[empty]".to_string();
    }
    let count = trimmed.chars().count();
    if count > max_length {
        let cut: String = trimmed.chars().take(max_length).collect();
        return format!("{cut}... [truncated]");
    }
    trimmed.to_string()
}

pub fn sanitize_user_content(text: Option<&str>) -> String {
    sanitize_user_content_opts(text, DEFAULT_MAX_LENGTH, false)
}

pub fn sanitize_text(text: &str) -> String {
    sanitize_user_content(Some(text))
}

/// Sanitise a single-line display name (username, title, sender name).
pub fn sanitize_name_opts(text: Option<&str>, max_length: usize) -> String {
    let result = sanitize_user_content_opts(text, max_length, false);
    let single = result.replace(['\n', '\r'], " ");
    let mut out = String::with_capacity(single.len());
    let mut prev_space = false;
    for ch in single.chars() {
        if ch == ' ' {
            if prev_space {
                continue;
            }
            prev_space = true;
        } else {
            prev_space = false;
        }
        out.push(ch);
    }
    out.trim().to_string()
}

pub fn sanitize_name(text: Option<&str>) -> String {
    sanitize_name_opts(text, NAME_MAX_LENGTH)
}

pub fn sanitize_name_str(text: &str) -> String {
    sanitize_name(Some(text))
}

/// Recursively sanitise every string value inside a JSON value.
pub fn sanitize_json(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, sanitize_json(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(sanitize_json).collect()),
        Value::String(s) => Value::String(sanitize_user_content(Some(&s))),
        other => other,
    }
}

/// Format tool output as `{"results": [...], ...metadata}`.
pub fn format_tool_result(
    records: Vec<serde_json::Value>,
    metadata: Option<serde_json::Map<String, serde_json::Value>>,
) -> String {
    let mut payload = serde_json::Map::new();
    payload.insert("results".to_string(), serde_json::Value::Array(records));
    if let Some(meta) = metadata {
        for (k, v) in meta {
            payload.insert(k, v);
        }
    }
    serde_json::Value::Object(payload).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_none() {
        assert_eq!(sanitize_user_content(None), "[empty]");
        assert_eq!(sanitize_user_content(Some("")), "[empty]");
        assert_eq!(sanitize_user_content(Some("   \n ")), "[empty]");
    }

    #[test]
    fn strips_control_and_invisible() {
        assert_eq!(sanitize_text("a\u{200b}b\u{0007}c"), "abc");
        assert_eq!(sanitize_text("keep\ttab\nline"), "keep\ttab\nline");
        assert_eq!(sanitize_text("x\u{202e}y"), "xy");
    }

    #[test]
    fn collapses_newlines_and_truncates() {
        assert_eq!(sanitize_text("a\n\n\n\nb"), "a\n\nb");
        let long = "x".repeat(5000);
        let out = sanitize_text(&long);
        assert!(out.ends_with("... [truncated]"));
        assert_eq!(out.chars().count(), 4096 + "... [truncated]".len());
    }

    #[test]
    fn preserve_emoji_keeps_zwj() {
        let family = "\u{1F468}\u{200d}\u{1F469}";
        assert_eq!(sanitize_user_content_opts(Some(family), 4096, true), family);
        assert_eq!(
            sanitize_user_content_opts(Some(family), 4096, false),
            "\u{1F468}\u{1F469}"
        );
    }

    #[test]
    fn names_are_single_line() {
        assert_eq!(sanitize_name(Some("Bad\nName   here")), "Bad Name here");
    }

    #[test]
    fn json_recursion() {
        let v = serde_json::json!({"a": ["x\u{200b}", {"b": ""}]});
        assert_eq!(
            sanitize_json(v),
            serde_json::json!({"a": ["x", {"b": "[empty]"}]})
        );
    }
}

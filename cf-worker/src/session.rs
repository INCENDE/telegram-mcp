//! Parser for Telethon's `StringSession` format, so a session generated with
//! the repo's `session_string_generator.py` can be reused here without
//! re-implementing the phone/2FA login flow.
//!
//! Layout (after the leading version char `1` and urlsafe-base64 decoding):
//! `>B{ip}sH256s` = dc_id (1 byte), server IP (4 or 16 bytes), port (u16 BE),
//! auth key (256 bytes).

use base64::Engine;

pub struct Session {
    pub dc_id: u8,
    pub auth_key: [u8; 256],
}

pub fn parse(string: &str) -> Result<Session, String> {
    let string = string.trim();
    let Some(rest) = string.strip_prefix('1') else {
        return Err("session string must start with version '1'".into());
    };
    let raw = base64::engine::general_purpose::URL_SAFE
        .decode(rest)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(rest))
        .map_err(|e| format!("session string is not valid base64: {e}"))?;

    let ip_len = match raw.len() {
        n if n == 1 + 4 + 2 + 256 => 4,
        n if n == 1 + 16 + 2 + 256 => 16,
        n => return Err(format!("unexpected session payload length {n}")),
    };
    let dc_id = raw[0];
    let key_start = 1 + ip_len + 2;
    let mut auth_key = [0u8; 256];
    auth_key.copy_from_slice(&raw[key_start..key_start + 256]);
    if auth_key.iter().all(|b| *b == 0) {
        return Err("session string carries no auth key (not logged in)".into());
    }
    Ok(Session { dc_id, auth_key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn make(dc: u8, ip: &[u8], key_byte: u8) -> String {
        let mut raw = vec![dc];
        raw.extend_from_slice(ip);
        raw.extend_from_slice(&443u16.to_be_bytes());
        raw.extend(std::iter::repeat(key_byte).take(256));
        format!("1{}", base64::engine::general_purpose::URL_SAFE.encode(raw))
    }

    #[test]
    fn parses_ipv4_session() {
        let s = parse(&make(2, &[149, 154, 167, 51], 0xab)).unwrap();
        assert_eq!(s.dc_id, 2);
        assert!(s.auth_key.iter().all(|b| *b == 0xab));
    }

    #[test]
    fn parses_ipv6_session() {
        let s = parse(&make(4, &[0u8; 16], 0x01)).unwrap();
        assert_eq!(s.dc_id, 4);
    }

    #[test]
    fn rejects_empty_key_and_bad_version() {
        assert!(parse(&make(2, &[1, 2, 3, 4], 0)).is_err());
        assert!(parse("2abc").is_err());
        assert!(parse("1notbase64!!").is_err());
    }
}

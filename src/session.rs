//! Session material: Telethon-compatible string sessions, Telethon `.session`
//! SQLite files, and their import into grammers session storages.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use grammers_session::storages::MemorySession;
use grammers_session::types::{
    ChannelKind, ChannelState, DcOption, PeerId, UpdateState, UpdatesState,
};
use grammers_session::types::{PeerAuth, PeerInfo};
use grammers_session::SessionData;
use grammers_session::{BoxFuture, Session};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::errors::ConfigError;

/// The auth material a Telethon session carries.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthMaterial {
    pub dc_id: i32,
    pub ip: IpAddr,
    pub port: u16,
    pub auth_key: [u8; 256],
}

impl std::fmt::Debug for AuthMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthMaterial")
            .field("dc_id", &self.dc_id)
            .field("ip", &self.ip)
            .field("port", &self.port)
            .field("auth_key", &"<redacted>")
            .finish()
    }
}

const STRING_SESSION_VERSION: u8 = b'1';

/// Parse a Telethon `StringSession` (`1` + urlsafe-base64 of `>B{4|16}sH256s`).
pub fn parse_string_session(value: &str) -> Result<AuthMaterial, ConfigError> {
    let value = value.trim();
    let body = value
        .strip_prefix(STRING_SESSION_VERSION as char)
        .ok_or_else(|| {
            ConfigError(
                "Unsupported session string version (expected a Telethon v1 string).".into(),
            )
        })?;
    let raw = base64::engine::general_purpose::URL_SAFE
        .decode(body)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body))
        .map_err(|_| ConfigError("Session string is not valid base64.".into()))?;
    let ip_len = match raw.len() {
        263 => 4,
        275 => 16,
        other => {
            return Err(ConfigError(format!(
                "Session string has unexpected length {other}."
            )))
        }
    };
    let dc_id = raw[0] as i32;
    let ip = if ip_len == 4 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&raw[1..5]);
        IpAddr::V4(Ipv4Addr::from(b))
    } else {
        let mut b = [0u8; 16];
        b.copy_from_slice(&raw[1..17]);
        IpAddr::V6(Ipv6Addr::from(b))
    };
    let port = u16::from_be_bytes([raw[1 + ip_len], raw[2 + ip_len]]);
    let mut auth_key = [0u8; 256];
    auth_key.copy_from_slice(&raw[3 + ip_len..3 + ip_len + 256]);
    Ok(AuthMaterial {
        dc_id,
        ip,
        port,
        auth_key,
    })
}

/// Encode auth material as a Telethon-compatible string session.
pub fn encode_string_session(m: &AuthMaterial) -> String {
    let mut raw = Vec::with_capacity(275);
    raw.push(m.dc_id as u8);
    match m.ip {
        IpAddr::V4(v4) => raw.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => raw.extend_from_slice(&v6.octets()),
    }
    raw.extend_from_slice(&m.port.to_be_bytes());
    raw.extend_from_slice(&m.auth_key);
    format!(
        "{}{}",
        STRING_SESSION_VERSION as char,
        base64::engine::general_purpose::URL_SAFE.encode(raw)
    )
}

/// One row of Telethon's `entities` table, already keyed by marked id.
#[derive(Debug, Clone)]
pub struct TelethonEntity {
    pub marked_id: i64,
    pub hash: i64,
    pub username: Option<String>,
    pub name: Option<String>,
}

/// Read the auth material (and cached entities) out of a Telethon `.session` file.
pub fn read_telethon_sqlite(
    path: &Path,
) -> Result<(Option<AuthMaterial>, Vec<TelethonEntity>), ConfigError> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| {
                ConfigError(format!(
                    "cannot open Telethon session {}: {e}",
                    path.display()
                ))
            })?;
    let material = conn
        .query_row(
            "SELECT dc_id, server_address, port, auth_key FROM sessions LIMIT 1",
            [],
            |row| {
                let dc_id: i32 = row.get(0)?;
                let addr: String = row.get(1)?;
                let port: i64 = row.get(2)?;
                let key: Vec<u8> = row.get(3)?;
                Ok((dc_id, addr, port, key))
            },
        )
        .ok()
        .and_then(|(dc_id, addr, port, key)| {
            let ip: IpAddr = addr.parse().ok()?;
            let mut auth_key = [0u8; 256];
            if key.len() != 256 {
                return None;
            }
            auth_key.copy_from_slice(&key);
            Some(AuthMaterial {
                dc_id,
                ip,
                port: port as u16,
                auth_key,
            })
        });
    let mut entities = Vec::new();
    if let Ok(mut stmt) = conn.prepare("SELECT id, hash, username, name FROM entities") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok(TelethonEntity {
                marked_id: row.get(0)?,
                hash: row.get(1)?,
                username: row.get(2).ok(),
                name: row.get(3).ok(),
            })
        }) {
            entities.extend(rows.flatten());
        }
    }
    Ok((material, entities))
}

/// Build grammers session data from Telethon material.
pub fn session_data_from(material: &AuthMaterial, entities: &[TelethonEntity]) -> SessionData {
    let mut data = SessionData::default();
    data.home_dc = material.dc_id;
    let entry = data.dc_options.entry(material.dc_id).or_insert_with(|| {
        grammers_session::types::DcOption {
            id: material.dc_id,
            ipv4: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 443),
            ipv6: SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 443, 0, 0),
            auth_key: None,
        }
    });
    match material.ip {
        IpAddr::V4(v4) => entry.ipv4 = SocketAddrV4::new(v4, material.port),
        IpAddr::V6(v6) => entry.ipv6 = SocketAddrV6::new(v6, material.port, 0, 0),
    }
    entry.auth_key = Some(material.auth_key);
    for ent in entities {
        if let Some(info) = peer_info_from_marked(ent.marked_id, ent.hash) {
            data.peer_infos.insert(info_id(&info), info);
        }
    }
    data
}

fn info_id(info: &PeerInfo) -> grammers_session::types::PeerId {
    use grammers_session::types::PeerId;
    match info {
        PeerInfo::User { id, .. } => PeerId::user_unchecked(*id),
        PeerInfo::Chat { id } => PeerId::chat_unchecked(*id),
        PeerInfo::Channel { id, .. } => PeerId::channel_unchecked(*id),
    }
}

/// Turn a Telethon marked id plus access hash into grammers peer info.
pub fn peer_info_from_marked(marked_id: i64, hash: i64) -> Option<PeerInfo> {
    if marked_id > 0 {
        Some(PeerInfo::User {
            id: marked_id,
            auth: Some(PeerAuth::from_hash(hash)),
            bot: None,
            is_self: None,
        })
    } else if marked_id <= -1_000_000_000_000 {
        Some(PeerInfo::Channel {
            id: -1_000_000_000_000 - marked_id,
            auth: Some(PeerAuth::from_hash(hash)),
            kind: None,
        })
    } else if marked_id < 0 {
        Some(PeerInfo::Chat { id: -marked_id })
    } else {
        None
    }
}

/// Where a session comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionSource {
    /// A Telethon string session (no persistence, like Telethon's StringSession).
    String(String),
    /// A named session persisted on disk. `name` has no extension.
    File(String),
}

impl SessionSource {
    /// Stable identity for lock keys, identical to the Python implementation.
    pub fn identity(&self) -> String {
        match self {
            SessionSource::String(s) => format!("string:{s}"),
            SessionSource::File(name) => {
                let path = telethon_session_path(name);
                let abs = std::path::absolute(&path).unwrap_or(path);
                format!("file:{}", abs.display())
            }
        }
    }
}

pub fn telethon_session_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from(name);
    if p.extension().map(|e| e == "session").unwrap_or(false) {
        return p;
    }
    p.set_extension("session");
    p
}

/// The grammers storage that sits beside a Telethon `.session` file.
pub fn grammers_session_path(name: &str) -> PathBuf {
    let base = telethon_session_path(name);
    let stem = base.with_extension("");
    PathBuf::from(format!("{}.grammers.session", stem.display()))
}

/// An opened session storage.
pub enum OpenedSession {
    Memory(Arc<MemorySession>),
    Sqlite(Arc<FileSession>),
}

/// Open (or create and import) the storage for a session source.
pub async fn open_session(source: &SessionSource) -> Result<OpenedSession, ConfigError> {
    match source {
        SessionSource::String(s) => {
            let material = parse_string_session(s)?;
            let data = session_data_from(&material, &[]);
            Ok(OpenedSession::Memory(Arc::new(MemorySession::from(data))))
        }
        SessionSource::File(name) => {
            let gpath = grammers_session_path(name);
            let existed = gpath.exists();
            if let Some(parent) = gpath.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            let session = FileSession::open(&gpath).map_err(|e| {
                ConfigError(format!("cannot open session {}: {e}", gpath.display()))
            })?;
            if !existed {
                let tpath = telethon_session_path(name);
                if tpath.exists() {
                    let (material, entities) = read_telethon_sqlite(&tpath)?;
                    if let Some(material) = material {
                        let data = session_data_from(&material, &entities);
                        data.import_to(&session).await.map_err(|e| {
                            ConfigError(format!("cannot import Telethon session: {e}"))
                        })?;
                        log::info!(
                            "Imported Telethon session {} into {}",
                            tpath.display(),
                            gpath.display()
                        );
                    }
                }
                restrict_permissions(&gpath);
            }
            Ok(OpenedSession::Sqlite(Arc::new(session)))
        }
    }
}

pub fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

// ---------------------------------------------------------------------------
// rusqlite-backed grammers Session storage
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum FileSessionError {
    #[error("session lock poisoned")]
    Poisoned,
    #[error("sqlite error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("bad address in session: {0}")]
    Addr(#[from] std::net::AddrParseError),
}

/// SQLite session storage with an in-memory cache and write-through persistence.
pub struct FileSession {
    data: Mutex<SessionData>,
    conn: Mutex<rusqlite::Connection>,
}

impl FileSession {
    pub fn open(path: &Path) -> Result<Self, FileSessionError> {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS dc (id INTEGER PRIMARY KEY, ipv4 TEXT NOT NULL, ipv6 TEXT NOT NULL, auth_key BLOB);
             CREATE TABLE IF NOT EXISTS peer (kind INTEGER NOT NULL, id INTEGER NOT NULL, auth INTEGER, bot INTEGER, is_self INTEGER, channel_kind INTEGER, PRIMARY KEY (kind, id));
             CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK (id = 1), pts INTEGER NOT NULL, qts INTEGER NOT NULL, date INTEGER NOT NULL, seq INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS channel_state (id INTEGER PRIMARY KEY, pts INTEGER NOT NULL);",
        )?;
        let mut data = SessionData::default();
        if let Ok(home) = conn.query_row("SELECT value FROM meta WHERE key = 'home_dc'", [], |r| {
            r.get::<_, String>(0)
        }) {
            if let Ok(v) = home.parse() {
                data.home_dc = v;
            }
        }
        {
            let mut stmt = conn.prepare("SELECT id, ipv4, ipv6, auth_key FROM dc")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i32>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<Vec<u8>>>(3)?,
                ))
            })?;
            for row in rows {
                let (id, v4, v6, key) = row?;
                let auth_key = key.and_then(|k| <[u8; 256]>::try_from(k).ok());
                data.dc_options.insert(
                    id,
                    DcOption {
                        id,
                        ipv4: v4.parse()?,
                        ipv6: v6.parse()?,
                        auth_key,
                    },
                );
            }
        }
        {
            let mut stmt =
                conn.prepare("SELECT kind, id, auth, bot, is_self, channel_kind FROM peer")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                ))
            })?;
            for row in rows {
                let (kind, id, auth, bot, is_self, ck) = row?;
                let auth = auth.map(PeerAuth::from_hash);
                let info = match kind {
                    0 => PeerInfo::User {
                        id,
                        auth,
                        bot: bot.map(|b| b != 0),
                        is_self: is_self.map(|b| b != 0),
                    },
                    1 => PeerInfo::Chat { id },
                    _ => PeerInfo::Channel {
                        id,
                        auth,
                        kind: match ck {
                            Some(1) => Some(ChannelKind::Broadcast),
                            Some(2) => Some(ChannelKind::Megagroup),
                            Some(3) => Some(ChannelKind::Gigagroup),
                            _ => None,
                        },
                    },
                };
                data.peer_infos.insert(info_id(&info), info);
            }
        }
        if let Ok((pts, qts, date, seq)) = conn.query_row(
            "SELECT pts, qts, date, seq FROM state WHERE id = 1",
            [],
            |r| {
                Ok((
                    r.get::<_, i32>(0)?,
                    r.get::<_, i32>(1)?,
                    r.get::<_, i32>(2)?,
                    r.get::<_, i32>(3)?,
                ))
            },
        ) {
            data.updates_state.pts = pts;
            data.updates_state.qts = qts;
            data.updates_state.date = date;
            data.updates_state.seq = seq;
        }
        {
            let mut stmt = conn.prepare("SELECT id, pts FROM channel_state")?;
            let rows = stmt.query_map([], |r| {
                Ok(ChannelState {
                    id: r.get(0)?,
                    pts: r.get(1)?,
                })
            })?;
            data.updates_state.channels = rows.flatten().collect();
        }
        Ok(Self {
            data: Mutex::new(data),
            conn: Mutex::new(conn),
        })
    }

    fn with_conn<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>,
    ) -> Result<T, FileSessionError> {
        let conn = self.conn.lock().map_err(|_| FileSessionError::Poisoned)?;
        Ok(f(&conn)?)
    }
}

fn peer_row(info: &PeerInfo) -> (i64, i64, Option<i64>, Option<i64>, Option<i64>, Option<i64>) {
    match info {
        PeerInfo::User {
            id,
            auth,
            bot,
            is_self,
        } => (
            0,
            *id,
            auth.map(|a| a.hash()),
            bot.map(i64::from),
            is_self.map(i64::from),
            None,
        ),
        PeerInfo::Chat { id } => (1, *id, None, None, None, None),
        PeerInfo::Channel { id, auth, kind } => (
            2,
            *id,
            auth.map(|a| a.hash()),
            None,
            None,
            kind.map(|k| match k {
                ChannelKind::Broadcast => 1,
                ChannelKind::Megagroup => 2,
                ChannelKind::Gigagroup => 3,
            }),
        ),
    }
}

impl Session for FileSession {
    type Error = FileSessionError;

    fn home_dc_id(&self) -> Result<i32, Self::Error> {
        Ok(self
            .data
            .lock()
            .map_err(|_| FileSessionError::Poisoned)?
            .home_dc)
    }

    fn set_home_dc_id(&self, dc_id: i32) -> BoxFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            self.data
                .lock()
                .map_err(|_| FileSessionError::Poisoned)?
                .home_dc = dc_id;
            self.with_conn(|c| {
                c.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES ('home_dc', ?)",
                    [dc_id.to_string()],
                )
                .map(|_| ())
            })
        })
    }

    fn dc_option(&self, dc_id: i32) -> Result<Option<DcOption>, Self::Error> {
        Ok(self
            .data
            .lock()
            .map_err(|_| FileSessionError::Poisoned)?
            .dc_options
            .get(&dc_id)
            .cloned())
    }

    fn set_dc_option(&self, dc_option: &DcOption) -> BoxFuture<'_, Result<(), Self::Error>> {
        let opt = dc_option.clone();
        Box::pin(async move {
            self.data
                .lock()
                .map_err(|_| FileSessionError::Poisoned)?
                .dc_options
                .insert(opt.id, opt.clone());
            self.with_conn(|c| {
                c.execute(
                    "INSERT OR REPLACE INTO dc (id, ipv4, ipv6, auth_key) VALUES (?, ?, ?, ?)",
                    rusqlite::params![
                        opt.id,
                        opt.ipv4.to_string(),
                        opt.ipv6.to_string(),
                        opt.auth_key.map(|k| k.to_vec())
                    ],
                )
                .map(|_| ())
            })
        })
    }

    fn peer(&self, peer: PeerId) -> BoxFuture<'_, Result<Option<PeerInfo>, Self::Error>> {
        Box::pin(async move {
            let data = self.data.lock().map_err(|_| FileSessionError::Poisoned)?;
            if peer == PeerId::self_user() {
                return Ok(data
                    .peer_infos
                    .values()
                    .find(|p| {
                        matches!(
                            p,
                            PeerInfo::User {
                                is_self: Some(true),
                                ..
                            }
                        )
                    })
                    .cloned());
            }
            Ok(data.peer_infos.get(&peer).cloned())
        })
    }

    fn cache_peer(&self, peer: &PeerInfo) -> BoxFuture<'_, Result<(), Self::Error>> {
        let peer = peer.clone();
        Box::pin(async move {
            let merged = {
                let mut data = self.data.lock().map_err(|_| FileSessionError::Poisoned)?;
                let id = info_id(&peer);
                match data.peer_infos.get_mut(&id) {
                    Some(existing) => {
                        existing.extend_info(&peer);
                        existing.clone()
                    }
                    None => {
                        data.peer_infos.insert(id, peer.clone());
                        peer
                    }
                }
            };
            let (kind, id, auth, bot, is_self, ck) = peer_row(&merged);
            self.with_conn(|c| {
                c.execute(
                    "INSERT OR REPLACE INTO peer (kind, id, auth, bot, is_self, channel_kind) VALUES (?, ?, ?, ?, ?, ?)",
                    rusqlite::params![kind, id, auth, bot, is_self, ck],
                )
                .map(|_| ())
            })
        })
    }

    fn updates_state(&self) -> BoxFuture<'_, Result<UpdatesState, Self::Error>> {
        Box::pin(async move {
            Ok(self
                .data
                .lock()
                .map_err(|_| FileSessionError::Poisoned)?
                .updates_state
                .clone())
        })
    }

    fn set_update_state(&self, update: UpdateState) -> BoxFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            let snapshot = {
                let mut data = self.data.lock().map_err(|_| FileSessionError::Poisoned)?;
                match update {
                    UpdateState::All(state) => data.updates_state = state,
                    UpdateState::Primary { pts, date, seq } => {
                        data.updates_state.pts = pts;
                        data.updates_state.date = date;
                        data.updates_state.seq = seq;
                    }
                    UpdateState::Secondary { qts } => data.updates_state.qts = qts,
                    UpdateState::Channel { id, pts } => {
                        match data.updates_state.channels.iter_mut().find(|c| c.id == id) {
                            Some(c) => c.pts = pts,
                            None => data.updates_state.channels.push(ChannelState { id, pts }),
                        }
                    }
                }
                data.updates_state.clone()
            };
            self.with_conn(|c| {
                c.execute(
                    "INSERT OR REPLACE INTO state (id, pts, qts, date, seq) VALUES (1, ?, ?, ?, ?)",
                    rusqlite::params![snapshot.pts, snapshot.qts, snapshot.date, snapshot.seq],
                )?;
                for ch in &snapshot.channels {
                    c.execute(
                        "INSERT OR REPLACE INTO channel_state (id, pts) VALUES (?, ?)",
                        rusqlite::params![ch.id, ch.pts],
                    )?;
                }
                Ok(())
            })
        })
    }
}

#[allow(dead_code)]
fn _assert_hashmap_used(_: HashMap<i32, i32>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuthMaterial {
        let mut key = [0u8; 256];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        AuthMaterial {
            dc_id: 2,
            ip: IpAddr::V4(Ipv4Addr::new(149, 154, 167, 51)),
            port: 443,
            auth_key: key,
        }
    }

    #[test]
    fn string_session_roundtrip_v4_and_v6() {
        let m = sample();
        let s = encode_string_session(&m);
        assert!(s.starts_with('1'));
        assert_eq!(parse_string_session(&s).unwrap(), m);
        let m6 = AuthMaterial {
            ip: IpAddr::V6("2001:67c:4e8:f002::a".parse().unwrap()),
            ..sample()
        };
        assert_eq!(
            parse_string_session(&encode_string_session(&m6)).unwrap(),
            m6
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_string_session("2abc").is_err());
        assert!(parse_string_session("1@@@").is_err());
        assert!(parse_string_session("1QUJD").is_err());
    }

    #[test]
    fn session_data_sets_home_dc_and_key() {
        let m = sample();
        let d = session_data_from(
            &m,
            &[TelethonEntity {
                marked_id: -1001234,
                hash: 5,
                username: None,
                name: None,
            }],
        );
        assert_eq!(d.home_dc, 2);
        assert_eq!(d.dc_options[&2].auth_key, Some(m.auth_key));
        assert_eq!(d.dc_options[&2].ipv4.port(), 443);
        assert_eq!(d.peer_infos.len(), 1);
    }

    #[test]
    fn marked_ids() {
        assert!(matches!(
            peer_info_from_marked(42, 1),
            Some(PeerInfo::User { id: 42, .. })
        ));
        assert!(matches!(
            peer_info_from_marked(-1000000000042, 1),
            Some(PeerInfo::Channel { id: 42, .. })
        ));
        assert!(matches!(
            peer_info_from_marked(-42, 1),
            Some(PeerInfo::Chat { id: 42 })
        ));
        assert!(peer_info_from_marked(0, 1).is_none());
    }

    #[test]
    fn paths() {
        assert_eq!(telethon_session_path("foo"), PathBuf::from("foo.session"));
        assert_eq!(
            telethon_session_path("foo.session"),
            PathBuf::from("foo.session")
        );
        assert_eq!(
            grammers_session_path("dir/foo"),
            PathBuf::from("dir/foo.grammers.session")
        );
    }

    #[test]
    fn reads_telethon_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.session");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE sessions (dc_id integer primary key, server_address text, port integer, auth_key blob, takeout_id integer);
             CREATE TABLE entities (id integer primary key, hash integer not null, username text, phone integer, name text, date integer);
             INSERT INTO entities VALUES (777, 99, 'bob', NULL, 'Bob', NULL);",
        )
        .unwrap();
        let m = sample();
        conn.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, NULL)",
            rusqlite::params![m.dc_id, m.ip.to_string(), m.port, m.auth_key.to_vec()],
        )
        .unwrap();
        drop(conn);
        let (got, ents) = read_telethon_sqlite(&path).unwrap();
        assert_eq!(got.unwrap(), m);
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].username.as_deref(), Some("bob"));
    }

    #[tokio::test]
    async fn file_session_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.grammers.session");
        let m = sample();
        {
            let s = FileSession::open(&path).unwrap();
            session_data_from(&m, &[]).import_to(&s).await.unwrap();
            s.cache_peer(&PeerInfo::User {
                id: 7,
                auth: Some(PeerAuth::from_hash(9)),
                bot: Some(false),
                is_self: Some(true),
            })
            .await
            .unwrap();
            s.set_update_state(UpdateState::Channel { id: 3, pts: 4 })
                .await
                .unwrap();
        }
        let s = FileSession::open(&path).unwrap();
        assert_eq!(s.home_dc_id().unwrap(), 2);
        assert_eq!(s.dc_option(2).unwrap().unwrap().auth_key, Some(m.auth_key));
        let me = s.peer(PeerId::self_user()).await.unwrap().unwrap();
        assert!(matches!(me, PeerInfo::User { id: 7, .. }));
        assert_eq!(
            s.updates_state().await.unwrap().channels,
            vec![ChannelState { id: 3, pts: 4 }]
        );
    }
}

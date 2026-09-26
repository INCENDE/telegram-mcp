//! Account discovery, client construction and connection lifecycle.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use grammers_client::client::{AutoSleep, ClientConfiguration, UpdatesConfiguration};
use grammers_client::sender::ConnectionParams;
use grammers_client::{Client, InvocationError, SenderPool};
use grammers_session::updates::UpdatesLike;
use sha1::Digest;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::config;
use crate::errors::ConfigError;
use crate::session::{open_session, OpenedSession, SessionSource};
use crate::singleton::{try_lock_exclusive, SessionLock};

/// One configured Telegram account.
pub struct Account {
    pub label: String,
    pub client: Client,
    pub source: SessionSource,
    updates: Mutex<Option<UnboundedReceiver<UpdatesLike>>>,
    me: tokio::sync::Mutex<Option<CachedMe>>,
    lock: Mutex<Option<SessionLock>>,
}

#[derive(Debug, Clone)]
pub struct CachedMe {
    pub id: i64,
    pub is_bot: bool,
    pub premium: bool,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
}

impl Account {
    /// Take the raw updates receiver (once) to drive `stream_updates`.
    pub fn take_updates(&self) -> Option<UnboundedReceiver<UpdatesLike>> {
        self.updates.lock().ok().and_then(|mut u| u.take())
    }

    pub fn session_identity(&self) -> String {
        self.source.identity()
    }

    /// Fetch and cache the logged-in user's basic facts.
    pub async fn me(&self) -> Result<CachedMe, InvocationError> {
        let user = self.client.get_me().await?;
        let premium = match &user.raw {
            grammers_tl_types::enums::User::User(u) => u.premium,
            _ => false,
        };
        let me = CachedMe {
            id: user.id().bare_id_unchecked(),
            is_bot: user.is_bot(),
            premium,
            username: user.username().map(str::to_string),
            first_name: user.first_name().map(str::to_string),
            last_name: user.last_name().map(str::to_string),
            phone: user.phone().map(str::to_string),
        };
        *self.me.lock().await = Some(me.clone());
        Ok(me)
    }

    /// Cached `me()` if available, else fetched.
    pub async fn cached_me(&self) -> Result<CachedMe, InvocationError> {
        if let Some(me) = self.me.lock().await.clone() {
            return Ok(me);
        }
        self.me().await
    }

    /// Fresh Premium check (Premium can expire or be bought at any time).
    pub async fn is_premium(&self) -> bool {
        self.me().await.map(|m| m.premium).unwrap_or(false)
    }

    pub async fn is_bot(&self) -> bool {
        self.cached_me().await.map(|m| m.is_bot).unwrap_or(false)
    }

    pub fn set_lock(&self, lock: SessionLock) {
        if let Ok(mut slot) = self.lock.lock() {
            *slot = Some(lock);
        }
    }

    pub fn release_lock(&self) {
        if let Ok(mut slot) = self.lock.lock() {
            if let Some(mut lock) = slot.take() {
                lock.release();
            }
        }
    }
}

/// All configured accounts, keyed by lower-case label.
pub struct Accounts {
    map: BTreeMap<String, Arc<Account>>,
}

impl Accounts {
    pub fn labels(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Arc<Account>)> {
        self.map.iter()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn is_multi(&self) -> bool {
        self.map.len() > 1
    }

    /// Resolve an optional account label to a client.
    pub fn get(&self, account: Option<&str>) -> Result<Arc<Account>, anyhow::Error> {
        let labels = || self.map.keys().cloned().collect::<Vec<_>>().join(", ");
        match account {
            None => {
                if self.map.len() == 1 {
                    Ok(self.map.values().next().unwrap().clone())
                } else {
                    anyhow::bail!("Account is required. Available accounts: {}", labels())
                }
            }
            Some(label) => {
                let key = label.to_ascii_lowercase();
                self.map.get(&key).cloned().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unknown account '{label}'. Available accounts: {}",
                        labels()
                    )
                })
            }
        }
    }

    pub fn first(&self) -> Option<Arc<Account>> {
        self.map.values().next().cloned()
    }
}

/// Handles to pooled-session lock files, kept open for the process lifetime.
static SESSION_POOL_LOCKS: OnceLock<Mutex<Vec<File>>> = OnceLock::new();

fn parse_session_pool() -> Vec<String> {
    config::env("TELEGRAM_SESSION_STRINGS")
        .map(|raw| {
            raw.split(|c: char| c.is_whitespace() || c == ',' || c == ';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Claim the first free session of a pool via an advisory file lock.
fn acquire_pooled_session(pool: &[String]) -> Result<String, ConfigError> {
    let mut lock_dir = std::env::temp_dir().join("telegram-mcp-session-locks");
    if std::fs::create_dir_all(&lock_dir).is_err() {
        lock_dir = std::env::temp_dir();
    }
    for (idx, session) in pool.iter().enumerate() {
        let digest: String = sha1::Sha1::digest(session.as_bytes())[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let lock_path = lock_dir.join(format!("session-{digest}.lock"));
        let Ok(mut fh) = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&lock_path)
        else {
            continue;
        };
        if !try_lock_exclusive(&fh) {
            continue;
        }
        let _ = fh.set_len(0);
        let _ = writeln!(fh, "pid={}", std::process::id());
        let _ = fh.flush();
        SESSION_POOL_LOCKS
            .get_or_init(|| Mutex::new(Vec::new()))
            .lock()
            .unwrap()
            .push(fh);
        eprintln!("Using Telegram session slot {}/{}.", idx + 1, pool.len());
        return Ok(session.clone());
    }
    Err(ConfigError(format!(
        "All {} pooled Telegram session(s) are already claimed by other live clients, so this one has no session to use. Add another session to TELEGRAM_SESSION_STRINGS (generate it with `telegram-mcp-generate-session`), one slot per concurrent client, or stop one of the other clients.",
        pool.len()
    )))
}

/// Scan the environment for configured accounts (label -> session source).
pub fn discover_sources() -> Result<BTreeMap<String, SessionSource>, ConfigError> {
    let mut sources = BTreeMap::new();
    const PREFIX_STR: &str = "TELEGRAM_SESSION_STRING_";
    const PREFIX_NAME: &str = "TELEGRAM_SESSION_NAME_";
    for (key, value) in std::env::vars() {
        if value.is_empty() {
            continue;
        }
        if let Some(label) = key.strip_prefix(PREFIX_STR) {
            if label == "S" {
                continue; // TELEGRAM_SESSION_STRINGS is the pool, not a label.
            }
            sources.insert(label.to_ascii_lowercase(), SessionSource::String(value));
        } else if let Some(label) = key.strip_prefix(PREFIX_NAME) {
            sources.insert(label.to_ascii_lowercase(), SessionSource::File(value));
        }
    }
    if !sources.contains_key("default") {
        let pool = parse_session_pool();
        if !pool.is_empty() {
            sources.insert(
                "default".into(),
                SessionSource::String(acquire_pooled_session(&pool)?),
            );
        } else if let Some(s) = config::env("TELEGRAM_SESSION_STRING") {
            sources.insert("default".into(), SessionSource::String(s));
        } else if let Some(n) = config::env("TELEGRAM_SESSION_NAME") {
            sources.insert("default".into(), SessionSource::File(n));
        }
    }
    if sources.is_empty() {
        return Err(ConfigError(
            "No Telegram session configured. Set TELEGRAM_SESSION_STRING or TELEGRAM_SESSION_STRING_<LABEL> in .env".into(),
        ));
    }
    Ok(sources)
}

pub fn api_credentials() -> Result<(i32, String), ConfigError> {
    let id = config::env("TELEGRAM_API_ID")
        .ok_or_else(|| ConfigError("TELEGRAM_API_ID and TELEGRAM_API_HASH must be set".into()))?;
    let hash = config::env("TELEGRAM_API_HASH")
        .ok_or_else(|| ConfigError("TELEGRAM_API_ID and TELEGRAM_API_HASH must be set".into()))?;
    let id: i32 = id
        .trim()
        .parse()
        .map_err(|_| ConfigError("TELEGRAM_API_ID must be an integer".into()))?;
    Ok((id, hash))
}

pub fn connection_params(label: &str) -> Result<ConnectionParams, ConfigError> {
    let mut params = ConnectionParams::default();
    let identity = config::device_identity();
    if let Some(v) = identity.device_model {
        params.device_model = v;
    }
    if let Some(v) = identity.system_version {
        params.system_version = v;
    }
    if let Some(v) = identity.app_version {
        params.app_version = v;
    }
    params.proxy_url = config::proxy_url_for_label(label)?;
    Ok(params)
}

/// Build an unconnected account from a session source.
pub async fn build_account(
    label: &str,
    source: SessionSource,
    api_id: i32,
) -> Result<Arc<Account>, ConfigError> {
    let params = connection_params(label)?;
    let opened = open_session(&source).await?;
    let pool = match opened {
        OpenedSession::Memory(s) => SenderPool::with_configuration(s, api_id, params),
        OpenedSession::Sqlite(s) => SenderPool::with_configuration(s, api_id, params),
    };
    let SenderPool {
        runner,
        handle,
        updates,
    } = pool;
    tokio::spawn(runner.run());
    let configuration = ClientConfiguration {
        retry_policy: Box::new(AutoSleep {
            threshold: Duration::from_secs(config::flood_sleep_threshold()),
            io_errors_as_flood_of: Some(Duration::from_secs(1)),
        }),
        auto_cache_peers: true,
    };
    let client = Client::with_configuration(handle, configuration);
    Ok(Arc::new(Account {
        label: label.to_string(),
        client,
        source,
        updates: Mutex::new(Some(updates)),
        me: tokio::sync::Mutex::new(None),
        lock: Mutex::new(None),
    }))
}

/// Discover and build every account.
pub async fn build_accounts() -> Result<Accounts, ConfigError> {
    let (api_id, _hash) = api_credentials()?;
    let mut map = BTreeMap::new();
    for (label, source) in discover_sources()? {
        map.insert(label.clone(), build_account(&label, source, api_id).await?);
    }
    Ok(Accounts { map })
}

fn is_auth_key_duplicated(err: &InvocationError) -> bool {
    matches!(err, InvocationError::Rpc(rpc) if rpc.is("AUTH_KEY_DUPLICATED"))
}

/// Take the session lock, connect, and verify authorization.
pub async fn connect_authorized(account: &Arc<Account>) -> Result<(), anyhow::Error> {
    let mut lock = SessionLock::new(&account.label, &account.session_identity());
    let grace = config::lock_grace_seconds();
    let shared = config::session_lock_shared();
    tokio::task::spawn_blocking(move || {
        lock.acquire(grace, crate::singleton::DEFAULT_POLL_INTERVAL, shared)
            .map(|_| lock)
    })
    .await
    .map_err(|e| anyhow::anyhow!("lock task failed: {e}"))?
    .map(|lock| account.set_lock(lock))?;

    let max_attempts = 4;
    let mut authorized = false;
    for attempt in 1..=max_attempts {
        match account.client.is_authorized().await {
            Ok(ok) => {
                authorized = ok;
                break;
            }
            Err(err) if is_auth_key_duplicated(&err) => {
                if attempt >= max_attempts {
                    return Err(err.into());
                }
                let delay = std::cmp::min(2u64.pow(attempt), 15);
                eprintln!(
                    "AuthKeyDuplicatedError connecting '{}' (attempt {attempt}/{max_attempts}): session in use from another IP. Retrying in {delay}s. If this persists, give each concurrent client its own session via TELEGRAM_SESSION_STRINGS or TELEGRAM_SESSION_STRING_<LABEL>.",
                    account.label
                );
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
            Err(err) => return Err(err.into()),
        }
    }
    if !authorized {
        anyhow::bail!(
            "Telegram client '{}' is not authorized. Interactive phone login is disabled for the MCP server because it runs over stdio. Generate a session string with `telegram-mcp-generate-session`, then set TELEGRAM_SESSION_STRING or TELEGRAM_SESSION_STRING_<LABEL> in .env. For existing file sessions, run the login outside the MCP server first.",
            account.label
        );
    }
    let _ = account.me().await;
    Ok(())
}

/// Warm the peer cache by walking the dialog list once (best effort).
pub async fn warm_cache(account: &Arc<Account>) {
    let mut dialogs = account.client.iter_dialogs();
    loop {
        match dialogs.next().await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(InvocationError::Rpc(rpc)) if rpc.is("BOT_METHOD_INVALID") => {
                eprintln!(
                    "Skipping entity cache pre-warm for bot client '{}' (dialogs restricted for bots).",
                    account.label
                );
                break;
            }
            Err(err) => {
                eprintln!("Entity cache warm failed for '{}': {err}", account.label);
                break;
            }
        }
    }
}

/// Drive the update stream for an account, feeding incoming messages to the
/// event tracker and syncing update state to the session periodically.
pub async fn run_updates(account: Arc<Account>, events: Arc<crate::events::IncomingTracker>) {
    let Some(receiver) = account.take_updates() else {
        return;
    };
    let mut stream = match account
        .client
        .stream_updates(
            receiver,
            UpdatesConfiguration {
                catch_up: false,
                update_queue_limit: Some(500),
            },
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            log::error!("cannot start update stream for '{}': {e}", account.label);
            return;
        }
    };
    let mut last_sync = std::time::Instant::now();
    loop {
        match stream.next().await {
            Ok(grammers_client::update::Update::NewMessage(msg)) => {
                let msg = msg.into_inner();
                if !msg.outgoing() {
                    events.on_incoming(&account, &msg).await;
                }
            }
            Ok(_) => {}
            Err(e) => {
                log::warn!("update stream error for '{}': {e}", account.label);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        if last_sync.elapsed() > Duration::from_secs(60) {
            let _ = stream.sync_update_state().await;
            last_sync = std::time::Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_parsing_splits_on_all_separators() {
        std::env::set_var("TELEGRAM_SESSION_STRINGS", "a, b;c\nd");
        assert_eq!(parse_session_pool(), vec!["a", "b", "c", "d"]);
        std::env::remove_var("TELEGRAM_SESSION_STRINGS");
    }
}

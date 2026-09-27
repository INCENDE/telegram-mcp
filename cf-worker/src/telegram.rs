//! Account-level operations on top of [`crate::mtproto`]: connecting to the
//! right datacenter, the login flow (code, 2FA password), and the calls the
//! tools need. Every function opens one WebSocket, does its work, and drops
//! it; the Durable Object that calls this serializes access so the auth key
//! is never used from two connections at once.

use grammers_crypto::two_factor_auth::{calculate_2fa, check_p_and_g};
use grammers_mtproto::mtp;
use grammers_tl_types::{self as tl, RemoteCall};
use serde::{Deserialize, Serialize};
use worker::{js_sys, WebSocket};

use crate::mtproto::{self, AuthKey, Connection, Error, Result};

/// What the Durable Object persists between requests.
#[derive(Serialize, Deserialize, Clone)]
pub struct Stored {
    pub dc_id: u8,
    pub key: Vec<u8>,
    pub time_offset: i32,
    pub salt: i64,
    pub stage: Stage,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub enum Stage {
    /// Auth key exists but nobody is logged in on it yet.
    KeyOnly,
    CodeSent {
        phone: String,
        phone_code_hash: String,
        via: String,
    },
    PasswordNeeded {
        phone: String,
        hint: String,
    },
    Authorized {
        user_id: i64,
        name: String,
    },
}

impl Stored {
    fn auth(&self) -> Result<AuthKey> {
        let key: [u8; 256] = self
            .key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Connection("stored auth key has wrong length".into()))?;
        Ok(AuthKey {
            key,
            time_offset: self.time_offset,
            salt: self.salt,
        })
    }

    fn from_auth(dc_id: u8, auth: &AuthKey, stage: Stage) -> Self {
        Stored {
            dc_id,
            key: auth.key.to_vec(),
            time_offset: auth.time_offset,
            salt: auth.salt,
            stage,
        }
    }
}

pub struct Config {
    pub api_id: i32,
    pub api_hash: String,
    /// Overrides the per-DC hostname when set (diagnostics only).
    pub ws_host: Option<String>,
}

impl Config {
    fn host(&self, dc_id: u8) -> Result<String> {
        if let Some(h) = &self.ws_host {
            return Ok(h.clone());
        }
        mtproto::dc_host(dc_id)
            .map(str::to_string)
            .ok_or_else(|| Error::Connection(format!("no websocket host known for DC {dc_id}")))
    }

    fn init<R: RemoteCall>(
        &self,
        query: R,
    ) -> tl::functions::InvokeWithLayer<tl::functions::InitConnection<R>> {
        tl::functions::InvokeWithLayer {
            layer: tl::LAYER,
            query: tl::functions::InitConnection {
                api_id: self.api_id,
                device_model: "Cloudflare Worker".into(),
                system_version: "workerd".into(),
                app_version: env!("CARGO_PKG_VERSION").into(),
                system_lang_code: "en".into(),
                lang_pack: "".into(),
                lang_code: "en".into(),
                proxy: None,
                params: None,
                query,
            },
        }
    }
}

/// Generate a fresh auth key on `dc_id`. The socket is returned so the caller
/// can keep using the encrypted connection built on it.
pub async fn new_key(cfg: &Config, dc_id: u8) -> Result<(WebSocket, Stored)> {
    let ws = mtproto::open_socket(&cfg.host(dc_id)?).await?;
    let (conn, auth) = Connection::plain(&ws)?.generate_auth_key().await?;
    drop(conn);
    Ok((ws, Stored::from_auth(dc_id, &auth, Stage::KeyOnly)))
}

async fn connect<'a>(
    ws: &'a WebSocket,
    stored: &Stored,
) -> Result<Connection<'a, mtp::Encrypted>> {
    Connection::encrypted(ws, &stored.auth()?)
}

/// Ask Telegram to send a login code. Follows `PHONE_MIGRATE_N` by generating
/// a key on the new datacenter; the returned `Stored` is what must be kept.
pub async fn send_code(cfg: &Config, mut stored: Stored, phone: &str) -> Result<Stored> {
    let request = cfg.init(tl::functions::auth::SendCode {
        phone_number: phone.to_string(),
        api_id: cfg.api_id,
        api_hash: cfg.api_hash.clone(),
        settings: tl::types::CodeSettings {
            allow_flashcall: false,
            current_number: false,
            allow_app_hash: false,
            allow_missed_call: false,
            allow_firebase: false,
            unknown_number: false,
            logout_tokens: None,
            token: None,
            app_sandbox: None,
        }
        .into(),
    });

    for _ in 0..2 {
        let ws = mtproto::open_socket(&cfg.host(stored.dc_id)?).await?;
        let mut conn = connect(&ws, &stored).await?;
        match conn.invoke(&request).await {
            Ok(tl::enums::auth::SentCode::Code(code)) => {
                stored.stage = Stage::CodeSent {
                    phone: phone.to_string(),
                    phone_code_hash: code.phone_code_hash,
                    via: describe_code_type(&code.r#type),
                };
                return Ok(stored);
            }
            Ok(tl::enums::auth::SentCode::Success(_)) => {
                return Err(Error::Connection("unexpected immediate sign-in".into()))
            }
            Ok(tl::enums::auth::SentCode::PaymentRequired(_)) => {
                return Err(Error::Connection(
                    "Telegram requires payment to send a code to this number".into(),
                ))
            }
            Err(e) => match e.migrate_to_dc() {
                Some(dc) if dc != stored.dc_id => {
                    drop(conn);
                    let (_ws, fresh) = new_key(cfg, dc).await?;
                    stored = fresh;
                    continue;
                }
                _ => return Err(e),
            },
        }
    }
    Err(Error::Connection("datacenter migration loop".into()))
}

fn describe_code_type(t: &tl::enums::auth::SentCodeType) -> String {
    use tl::enums::auth::SentCodeType as T;
    match t {
        T::App(_) => "the Telegram app (check your other devices)".into(),
        T::Sms(_) | T::SmsWord(_) | T::SmsPhrase(_) => "SMS".into(),
        T::Call(_) => "a phone call".into(),
        T::FlashCall(_) | T::MissedCall(_) => "a missed call (the code is in the number)".into(),
        T::EmailCode(_) => "email".into(),
        T::FragmentSms(_) => "Fragment".into(),
        T::FirebaseSms(_) => "SMS".into(),
        T::SetUpEmailRequired(_) => "email (setup required)".into(),
    }
}

pub enum SignIn {
    Done(Stored),
    PasswordNeeded(Stored),
}

/// Complete the login with the code Telegram sent.
pub async fn sign_in(cfg: &Config, mut stored: Stored, code: &str) -> Result<SignIn> {
    let (phone, phone_code_hash) = match &stored.stage {
        Stage::CodeSent {
            phone,
            phone_code_hash,
            ..
        } => (phone.clone(), phone_code_hash.clone()),
        _ => return Err(Error::Connection("no code was requested".into())),
    };
    let ws = mtproto::open_socket(&cfg.host(stored.dc_id)?).await?;
    let mut conn = connect(&ws, &stored).await?;
    let request = cfg.init(tl::functions::auth::SignIn {
        phone_number: phone.clone(),
        phone_code_hash,
        phone_code: Some(code.trim().to_string()),
        email_verification: None,
    });
    match conn.invoke(&request).await {
        Ok(auth) => {
            stored.stage = authorized_stage(auth)?;
            Ok(SignIn::Done(stored))
        }
        Err(e) if e.is("SESSION_PASSWORD_NEEDED") => {
            let pw = conn.invoke(&tl::functions::account::GetPassword {}).await?;
            let tl::enums::account::Password::Password(pw) = pw;
            stored.stage = Stage::PasswordNeeded {
                phone,
                hint: pw.hint.unwrap_or_default(),
            };
            Ok(SignIn::PasswordNeeded(stored))
        }
        Err(e) => Err(e),
    }
}

/// Second factor: SRP proof of the cloud password.
pub async fn check_password(cfg: &Config, mut stored: Stored, password: &str) -> Result<Stored> {
    if !matches!(stored.stage, Stage::PasswordNeeded { .. }) {
        return Err(Error::Connection("no password was requested".into()));
    }
    let ws = mtproto::open_socket(&cfg.host(stored.dc_id)?).await?;
    let mut conn = connect(&ws, &stored).await?;

    // Parameters are single-use (srp_b), so always fetch fresh ones.
    let pw = conn
        .invoke(&cfg.init(tl::functions::account::GetPassword {}))
        .await?;
    let tl::enums::account::Password::Password(pw) = pw;
    let algo = match pw.current_algo {
        Some(tl::enums::PasswordKdfAlgo::Sha256Sha256Pbkdf2Hmacsha512iter100000Sha256ModPow(a)) => a,
        _ => return Err(Error::Connection("unsupported password KDF".into())),
    };
    if !check_p_and_g(&algo.p, &algo.g) {
        return Err(Error::Connection("server sent invalid SRP parameters".into()));
    }
    let (srp_b, srp_id) = match (pw.srp_b, pw.srp_id) {
        (Some(b), Some(id)) => (b, id),
        _ => return Err(Error::Connection("server sent no SRP challenge".into())),
    };
    let (m1, g_a) = calculate_2fa(
        &algo.salt1,
        &algo.salt2,
        &algo.p,
        &algo.g,
        srp_b,
        pw.secure_random,
        password,
    );
    let auth = conn
        .invoke(&tl::functions::auth::CheckPassword {
            password: tl::enums::InputCheckPasswordSrp::Srp(tl::types::InputCheckPasswordSrp {
                srp_id,
                a: g_a.to_vec(),
                m1: m1.to_vec(),
            }),
        })
        .await?;
    stored.stage = authorized_stage(auth)?;
    Ok(stored)
}

fn authorized_stage(auth: tl::enums::auth::Authorization) -> Result<Stage> {
    match auth {
        tl::enums::auth::Authorization::Authorization(a) => {
            let (user_id, name) = match a.user {
                tl::enums::User::User(u) => (u.id, display_name(&u)),
                tl::enums::User::Empty(u) => (u.id, String::new()),
            };
            Ok(Stage::Authorized { user_id, name })
        }
        tl::enums::auth::Authorization::SignUpRequired(_) => Err(Error::Connection(
            "this phone number has no Telegram account".into(),
        )),
    }
}

pub fn display_name(u: &tl::types::User) -> String {
    let full = [u.first_name.as_deref(), u.last_name.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    if full.is_empty() {
        u.username.clone().unwrap_or_else(|| format!("user {}", u.id))
    } else {
        full
    }
}

/// Invalidate the authorization on Telegram's side.
pub async fn log_out(cfg: &Config, stored: &Stored) -> Result<()> {
    let ws = mtproto::open_socket(&cfg.host(stored.dc_id)?).await?;
    let mut conn = connect(&ws, stored).await?;
    conn.invoke(&cfg.init(tl::functions::auth::LogOut {}))
        .await?;
    Ok(())
}

/// Import an authorization generated elsewhere (Telethon session string).
pub fn import(dc_id: u8, key: [u8; 256]) -> Stored {
    Stored::from_auth(
        dc_id,
        &AuthKey {
            key,
            time_offset: 0,
            salt: 0,
        },
        // We do not know who owns the key until a call succeeds; the first
        // successful `dialogs` fills this in.
        Stage::KeyOnly,
    )
}

/// Connection diagnostics that need no account: open the socket to `host`
/// and run the first, unencrypted step of key generation (`req_pq_multi`).
/// Reports how far it got and how long each phase took.
pub async fn diag(host: &str) -> serde_json::Value {
    let t0 = js_sys::Date::now();
    let ws = match mtproto::open_socket(host).await {
        Ok(ws) => ws,
        Err(e) => {
            return serde_json::json!({"host": host, "phase": "connect", "error": e.to_string(),
                "ms": js_sys::Date::now() - t0})
        }
    };
    let t1 = js_sys::Date::now();
    let result = async {
        let mut conn = Connection::plain(&ws)?;
        let (request, _data) = grammers_mtproto::authentication::step1()?;
        conn.invoke(&request).await?;
        Ok::<_, Error>(())
    }
    .await;
    let t2 = js_sys::Date::now();
    let _ = ws.close(Some(1000), Some("diag"));
    match result {
        Ok(()) => serde_json::json!({"host": host, "phase": "done", "connect_ms": t1 - t0,
            "req_pq_ms": t2 - t1}),
        Err(e) => serde_json::json!({"host": host, "phase": "req_pq_multi", "error": e.to_string(),
            "connect_ms": t1 - t0, "ms": t2 - t1}),
    }
}

/// Confirm an imported key is authorized and learn whose it is.
pub async fn whoami(cfg: &Config, stored: &Stored) -> Result<Stage> {
    let ws = mtproto::open_socket(&cfg.host(stored.dc_id)?).await?;
    let mut conn = connect(&ws, stored).await?;
    let users = conn
        .invoke(&cfg.init(tl::functions::users::GetUsers {
            id: vec![tl::enums::InputUser::UserSelf],
        }))
        .await?;
    match users.into_iter().next() {
        Some(tl::enums::User::User(u)) => Ok(Stage::Authorized {
            user_id: u.id,
            name: display_name(&u),
        }),
        _ => Err(Error::Connection("Telegram returned no user for this key".into())),
    }
}

#[derive(Serialize)]
pub struct DialogOut {
    pub id: i64,
    pub kind: &'static str,
    pub name: String,
    pub unread: i32,
}

pub async fn dialogs(cfg: &Config, stored: &Stored, limit: i32) -> Result<Vec<DialogOut>> {
    let ws = mtproto::open_socket(&cfg.host(stored.dc_id)?).await?;
    let mut conn = connect(&ws, stored).await?;
    let result = conn
        .invoke(&cfg.init(tl::functions::messages::GetDialogs {
            exclude_pinned: false,
            folder_id: None,
            offset_date: 0,
            offset_id: 0,
            offset_peer: tl::enums::InputPeer::Empty,
            limit,
            hash: 0,
        }))
        .await?;
    let _ = ws.close(Some(1000), Some("done"));
    Ok(summarize(result))
}

fn summarize(result: tl::enums::messages::Dialogs) -> Vec<DialogOut> {
    let (dialogs, chats, users) = match result {
        tl::enums::messages::Dialogs::Dialogs(d) => (d.dialogs, d.chats, d.users),
        tl::enums::messages::Dialogs::Slice(d) => (d.dialogs, d.chats, d.users),
        tl::enums::messages::Dialogs::NotModified(_) => return Vec::new(),
    };

    let user_name = |id: i64| -> String {
        users
            .iter()
            .find_map(|u| match u {
                tl::enums::User::User(u) if u.id == id => Some(display_name(u)),
                _ => None,
            })
            .unwrap_or_else(|| format!("user {id}"))
    };
    let chat_title = |id: i64| -> String {
        chats
            .iter()
            .find_map(|c| match c {
                tl::enums::Chat::Chat(c) if c.id == id => Some(c.title.clone()),
                tl::enums::Chat::Channel(c) if c.id == id => Some(c.title.clone()),
                _ => None,
            })
            .unwrap_or_else(|| format!("chat {id}"))
    };

    dialogs
        .into_iter()
        .filter_map(|d| match d {
            tl::enums::Dialog::Dialog(d) => Some(d),
            tl::enums::Dialog::Folder(_) => None,
        })
        .map(|d| {
            let (id, kind, name) = match &d.peer {
                tl::enums::Peer::User(p) => (p.user_id, "user", user_name(p.user_id)),
                tl::enums::Peer::Chat(p) => (p.chat_id, "group", chat_title(p.chat_id)),
                tl::enums::Peer::Channel(p) => {
                    (p.channel_id, "channel", chat_title(p.channel_id))
                }
            };
            DialogOut {
                id,
                kind,
                name,
                unread: d.unread_count,
            }
        })
        .collect()
}

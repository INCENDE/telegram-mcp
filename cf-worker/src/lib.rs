//! Feasibility spike: talk MTProto to Telegram from a Cloudflare Worker.
//!
//! `GET /spike` (bearer-token protected) connects to the account's home
//! datacenter with the auth key from `TELEGRAM_SESSION_STRING`, runs
//! `initConnection` wrapping `messages.getDialogs`, and returns the chat list
//! plus timing so we can judge latency and CPU cost.

mod mtproto;
mod session;

use grammers_tl_types as tl;
use serde::Serialize;
use worker::*;

#[derive(Serialize)]
struct DialogOut {
    id: i64,
    kind: &'static str,
    name: String,
    unread: i32,
}

#[derive(Serialize)]
struct SpikeOut {
    dc: u8,
    dialogs: Vec<DialogOut>,
    total_ms: f64,
    connect_ms: f64,
    rpc_ms: f64,
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    if req.path() != "/spike" {
        return Response::error("not found", 404);
    }
    if !authorized(&req, &env)? {
        return Response::error("unauthorized", 401);
    }

    match run_spike(&env).await {
        Ok(out) => Response::from_json(&out),
        Err(e) => Response::error(e, 502),
    }
}

fn authorized(req: &Request, env: &Env) -> Result<bool> {
    let expected = env.secret("SPIKE_TOKEN")?.to_string();
    let header = req.headers().get("authorization")?.unwrap_or_default();
    Ok(!expected.is_empty() && header == format!("Bearer {expected}"))
}

async fn run_spike(env: &Env) -> std::result::Result<SpikeOut, String> {
    let api_id: i32 = env
        .secret("TELEGRAM_API_ID")
        .map_err(|e| e.to_string())?
        .to_string()
        .parse()
        .map_err(|_| "TELEGRAM_API_ID is not an integer".to_string())?;
    let session = session::parse(
        &env.secret("TELEGRAM_SESSION_STRING")
            .map_err(|e| e.to_string())?
            .to_string(),
    )?;

    let t0 = js_sys::Date::now();
    let host = match env.var("TELEGRAM_WS_HOST") {
        Ok(v) => v.to_string(),
        Err(_) => mtproto::dc_host(session.dc_id)
            .ok_or_else(|| format!("no websocket host known for DC {}", session.dc_id))?
            .to_string(),
    };
    let ws = mtproto::open_socket(&host).await.map_err(|e| e.to_string())?;
    let mut conn = mtproto::Connection::new(&ws, session.auth_key).map_err(|e| e.to_string())?;
    let t1 = js_sys::Date::now();

    let request = tl::functions::InvokeWithLayer {
        layer: tl::LAYER,
        query: tl::functions::InitConnection {
            api_id,
            device_model: "Cloudflare Worker".into(),
            system_version: "workerd".into(),
            app_version: "0.1.0".into(),
            system_lang_code: "en".into(),
            lang_pack: "".into(),
            lang_code: "en".into(),
            proxy: None,
            params: None,
            query: tl::functions::messages::GetDialogs {
                exclude_pinned: false,
                folder_id: None,
                offset_date: 0,
                offset_id: 0,
                offset_peer: tl::enums::InputPeer::Empty,
                limit: 20,
                hash: 0,
            },
        },
    };
    let dialogs = conn.invoke(&request).await.map_err(|e| e.to_string())?;
    let t2 = js_sys::Date::now();
    let _ = ws.close(Some(1000), Some("done"));

    Ok(SpikeOut {
        dc: session.dc_id,
        dialogs: summarize(dialogs),
        total_ms: t2 - t0,
        connect_ms: t1 - t0,
        rpc_ms: t2 - t1,
    })
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
                tl::enums::User::User(u) if u.id == id => Some(
                    [u.first_name.as_deref(), u.last_name.as_deref()]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
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

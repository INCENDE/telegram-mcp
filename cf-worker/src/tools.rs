//! The Telegram operations behind the MCP tools: list chats, read history,
//! search, send. Each call opens one connection and drops it.
//!
//! Telegram addresses users and channels by (id, access_hash); the hash is
//! only learned from responses that include the entity. Every call here
//! records the entities it sees in a peer cache the Durable Object persists,
//! and a chat id the cache does not know triggers a dialog refresh.

use std::collections::HashMap;

use grammers_tl_types as tl;
use serde::{Deserialize, Serialize};
use worker::js_sys;

use crate::mtproto::{self, Error, Result};
use crate::telegram::{connect, display_name, i64_string, Config, Stored};

#[derive(Serialize, Deserialize, Clone)]
pub struct PeerRef {
    pub kind: PeerKind,
    #[serde(with = "i64_string")]
    pub access_hash: i64,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PeerKind {
    User,
    Group,
    Channel,
}

/// id → how to address it. Persisted by the Durable Object between calls.
pub type PeerCache = HashMap<i64, PeerRef>;

impl PeerRef {
    fn input_peer(&self, id: i64) -> tl::enums::InputPeer {
        match self.kind {
            PeerKind::User => tl::enums::InputPeer::User(tl::types::InputPeerUser {
                user_id: id,
                access_hash: self.access_hash,
            }),
            PeerKind::Group => tl::enums::InputPeer::Chat(tl::types::InputPeerChat { chat_id: id }),
            PeerKind::Channel => tl::enums::InputPeer::Channel(tl::types::InputPeerChannel {
                channel_id: id,
                access_hash: self.access_hash,
            }),
        }
    }
}

/// Record every user and chat in a response into the cache.
fn absorb(cache: &mut PeerCache, users: &[tl::enums::User], chats: &[tl::enums::Chat]) {
    for u in users {
        if let tl::enums::User::User(u) = u {
            cache.insert(
                u.id,
                PeerRef {
                    kind: PeerKind::User,
                    access_hash: u.access_hash.unwrap_or(0),
                    name: display_name(u),
                },
            );
        }
    }
    for c in chats {
        match c {
            tl::enums::Chat::Chat(c) => {
                cache.insert(
                    c.id,
                    PeerRef {
                        kind: PeerKind::Group,
                        access_hash: 0,
                        name: c.title.clone(),
                    },
                );
            }
            tl::enums::Chat::Channel(c) => {
                cache.insert(
                    c.id,
                    PeerRef {
                        kind: PeerKind::Channel,
                        access_hash: c.access_hash.unwrap_or(0),
                        name: c.title.clone(),
                    },
                );
            }
            _ => {}
        }
    }
}

fn peer_id(p: &tl::enums::Peer) -> i64 {
    match p {
        tl::enums::Peer::User(p) => p.user_id,
        tl::enums::Peer::Chat(p) => p.chat_id,
        tl::enums::Peer::Channel(p) => p.channel_id,
    }
}

fn name_of(cache: &PeerCache, id: i64) -> String {
    cache
        .get(&id)
        .map(|p| p.name.clone())
        .unwrap_or_else(|| format!("#{id}"))
}

fn iso_date(unix: i32) -> String {
    let d = js_sys::Date::new(&js_sys::Number::from(unix as f64 * 1000.0).into());
    let s: String = d.to_iso_string().into();
    // Drop milliseconds: "2026-09-27T02:15:00.000Z" → "2026-09-27T02:15:00Z"
    match s.find('.') {
        Some(i) => format!("{}Z", &s[..i]),
        None => s,
    }
}

#[derive(Serialize)]
pub struct ChatOut {
    pub id: i64,
    pub kind: PeerKind,
    pub name: String,
    pub unread: i32,
}

#[derive(Serialize)]
pub struct MessageOut {
    pub id: i32,
    pub date: String,
    pub from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat: Option<String>,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<i32>,
}

fn media_kind(m: &tl::enums::MessageMedia) -> &'static str {
    use tl::enums::MessageMedia as M;
    match m {
        M::Photo(_) => "photo",
        M::Document(_) => "document",
        M::Geo(_) | M::GeoLive(_) | M::Venue(_) => "location",
        M::Contact(_) => "contact",
        M::Poll(_) => "poll",
        M::WebPage(_) => "link_preview",
        M::Dice(_) => "dice",
        _ => "other",
    }
}

fn render(cache: &PeerCache, m: &tl::enums::Message, with_chat: bool) -> Option<MessageOut> {
    match m {
        tl::enums::Message::Message(m) => Some(MessageOut {
            id: m.id,
            date: iso_date(m.date),
            from: m
                .from_id
                .as_ref()
                .map(|p| name_of(cache, peer_id(p)))
                .unwrap_or_else(|| name_of(cache, peer_id(&m.peer_id))),
            chat: with_chat.then(|| name_of(cache, peer_id(&m.peer_id))),
            text: m.message.clone(),
            media: m.media.as_ref().map(media_kind),
            reply_to: match &m.reply_to {
                Some(tl::enums::MessageReplyHeader::Header(h)) => h.reply_to_msg_id,
                _ => None,
            },
        }),
        tl::enums::Message::Service(m) => Some(MessageOut {
            id: m.id,
            date: iso_date(m.date),
            from: m
                .from_id
                .as_ref()
                .map(|p| name_of(cache, peer_id(p)))
                .unwrap_or_default(),
            chat: with_chat.then(|| name_of(cache, peer_id(&m.peer_id))),
            text: "[service message]".into(),
            media: None,
            reply_to: None,
        }),
        tl::enums::Message::Empty(_) => None,
    }
}

fn split_messages(
    r: tl::enums::messages::Messages,
) -> (Vec<tl::enums::Message>, Vec<tl::enums::Chat>, Vec<tl::enums::User>) {
    use tl::enums::messages::Messages as R;
    match r {
        R::Messages(m) => (m.messages, m.chats, m.users),
        R::Slice(m) => (m.messages, m.chats, m.users),
        R::ChannelMessages(m) => (m.messages, m.chats, m.users),
        R::NotModified(_) => (vec![], vec![], vec![]),
    }
}

pub async fn list_chats(
    cfg: &Config,
    stored: &Stored,
    cache: &mut PeerCache,
    limit: i32,
) -> Result<Vec<ChatOut>> {
    let ws = mtproto::open_socket(&cfg.host(stored.dc_id)?).await?;
    let mut conn = connect(&ws, stored).await?;
    let result = conn
        .invoke(&cfg.init(tl::functions::messages::GetDialogs {
            exclude_pinned: false,
            folder_id: None,
            offset_date: 0,
            offset_id: 0,
            offset_peer: tl::enums::InputPeer::Empty,
            limit: limit.clamp(1, 100),
            hash: 0,
        }))
        .await?;
    let _ = ws.close(Some(1000), Some("done"));

    let (dialogs, chats, users) = match result {
        tl::enums::messages::Dialogs::Dialogs(d) => (d.dialogs, d.chats, d.users),
        tl::enums::messages::Dialogs::Slice(d) => (d.dialogs, d.chats, d.users),
        tl::enums::messages::Dialogs::NotModified(_) => return Ok(Vec::new()),
    };
    absorb(cache, &users, &chats);

    Ok(dialogs
        .into_iter()
        .filter_map(|d| match d {
            tl::enums::Dialog::Dialog(d) => Some(d),
            tl::enums::Dialog::Folder(_) => None,
        })
        .filter_map(|d| {
            let id = peer_id(&d.peer);
            let p = cache.get(&id)?;
            Some(ChatOut {
                id,
                kind: p.kind,
                name: p.name.clone(),
                unread: d.unread_count,
            })
        })
        .collect())
}

/// Find how to address `chat_id`, refreshing the dialog list once if the
/// cache does not know it.
async fn resolve(
    cfg: &Config,
    stored: &Stored,
    cache: &mut PeerCache,
    chat_id: i64,
) -> Result<tl::enums::InputPeer> {
    if !cache.contains_key(&chat_id) {
        list_chats(cfg, stored, cache, 100).await?;
    }
    cache
        .get(&chat_id)
        .map(|p| p.input_peer(chat_id))
        .ok_or_else(|| {
            Error::Connection(format!(
                "chat {chat_id} is not in your recent dialogs; call list_chats and use an id from there"
            ))
        })
}

pub async fn get_messages(
    cfg: &Config,
    stored: &Stored,
    cache: &mut PeerCache,
    chat_id: i64,
    limit: i32,
    before_id: Option<i32>,
) -> Result<Vec<MessageOut>> {
    let peer = resolve(cfg, stored, cache, chat_id).await?;
    let ws = mtproto::open_socket(&cfg.host(stored.dc_id)?).await?;
    let mut conn = connect(&ws, stored).await?;
    let result = conn
        .invoke(&cfg.init(tl::functions::messages::GetHistory {
            peer,
            offset_id: before_id.unwrap_or(0),
            offset_date: 0,
            add_offset: 0,
            limit: limit.clamp(1, 100),
            max_id: 0,
            min_id: 0,
            hash: 0,
        }))
        .await?;
    let _ = ws.close(Some(1000), Some("done"));

    let (messages, chats, users) = split_messages(result);
    absorb(cache, &users, &chats);
    let mut out: Vec<_> = messages.iter().filter_map(|m| render(cache, m, false)).collect();
    out.reverse(); // Telegram returns newest first; read top to bottom instead.
    Ok(out)
}

pub async fn search_messages(
    cfg: &Config,
    stored: &Stored,
    cache: &mut PeerCache,
    query: &str,
    chat_id: Option<i64>,
    limit: i32,
) -> Result<Vec<MessageOut>> {
    let peer = match chat_id {
        Some(id) => Some(resolve(cfg, stored, cache, id).await?),
        None => None,
    };
    let ws = mtproto::open_socket(&cfg.host(stored.dc_id)?).await?;
    let mut conn = connect(&ws, stored).await?;
    let limit = limit.clamp(1, 100);
    let result = match peer {
        Some(peer) => {
            conn.invoke(&cfg.init(tl::functions::messages::Search {
                peer,
                q: query.to_string(),
                from_id: None,
                saved_peer_id: None,
                saved_reaction: None,
                top_msg_id: None,
                filter: tl::enums::MessagesFilter::InputMessagesFilterEmpty,
                min_date: 0,
                max_date: 0,
                offset_id: 0,
                add_offset: 0,
                limit,
                max_id: 0,
                min_id: 0,
                hash: 0,
            }))
            .await?
        }
        None => {
            conn.invoke(&cfg.init(tl::functions::messages::SearchGlobal {
                broadcasts_only: false,
                groups_only: false,
                users_only: false,
                folder_id: None,
                q: query.to_string(),
                filter: tl::enums::MessagesFilter::InputMessagesFilterEmpty,
                min_date: 0,
                max_date: 0,
                offset_rate: 0,
                offset_peer: tl::enums::InputPeer::Empty,
                offset_id: 0,
                limit,
            }))
            .await?
        }
    };
    let _ = ws.close(Some(1000), Some("done"));

    let (messages, chats, users) = split_messages(result);
    absorb(cache, &users, &chats);
    let mut out: Vec<_> = messages
        .iter()
        .filter_map(|m| render(cache, m, chat_id.is_none()))
        .collect();
    out.reverse();
    Ok(out)
}

pub struct Sent {
    pub message_id: Option<i32>,
    pub chat: String,
}

pub async fn send_message(
    cfg: &Config,
    stored: &Stored,
    cache: &mut PeerCache,
    chat_id: i64,
    text: &str,
    reply_to: Option<i32>,
) -> Result<Sent> {
    let peer = resolve(cfg, stored, cache, chat_id).await?;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|_| Error::Connection("no randomness".into()))?;
    let ws = mtproto::open_socket(&cfg.host(stored.dc_id)?).await?;
    let mut conn = connect(&ws, stored).await?;
    let updates = conn
        .invoke(&cfg.init(tl::functions::messages::SendMessage {
            no_webpage: false,
            silent: false,
            background: false,
            clear_draft: true,
            noforwards: false,
            update_stickersets_order: false,
            invert_media: false,
            allow_paid_floodskip: false,
            peer,
            reply_to: reply_to.map(|id| {
                tl::enums::InputReplyTo::Message(tl::types::InputReplyToMessage {
                    reply_to_msg_id: id,
                    top_msg_id: None,
                    reply_to_peer_id: None,
                    quote_text: None,
                    quote_entities: None,
                    quote_offset: None,
                    monoforum_peer_id: None,
                    todo_item_id: None,
                    poll_option: None,
                })
            }),
            message: text.to_string(),
            random_id: i64::from_le_bytes(random),
            reply_markup: None,
            entities: None,
            schedule_date: None,
            schedule_repeat_period: None,
            send_as: None,
            quick_reply_shortcut: None,
            effect: None,
            allow_paid_stars: None,
            suggested_post: None,
            rich_message: None,
        }))
        .await?;
    let _ = ws.close(Some(1000), Some("done"));

    let message_id = match &updates {
        tl::enums::Updates::UpdateShortSentMessage(u) => Some(u.id),
        tl::enums::Updates::Updates(u) => u.updates.iter().find_map(sent_id),
        tl::enums::Updates::Combined(u) => u.updates.iter().find_map(sent_id),
        _ => None,
    };
    Ok(Sent {
        message_id,
        chat: name_of(cache, chat_id),
    })
}

fn sent_id(u: &tl::enums::Update) -> Option<i32> {
    match u {
        tl::enums::Update::MessageId(m) => Some(m.id),
        tl::enums::Update::NewMessage(m) => Some(m.message.id()),
        tl::enums::Update::NewChannelMessage(m) => Some(m.message.id()),
        _ => None,
    }
}

//! Minimal MTProto client driver for a Cloudflare Worker.
//!
//! `grammers-mtproto` is sans-IO: it encodes/decrypts frames and leaves the
//! network to us. Here the network is an outbound WebSocket to one of
//! Telegram's `*.web.telegram.org/apiws` endpoints, using the obfuscated
//! intermediate transport (what Telegram requires over WS).
//!
//! The connection is request/response only: one RPC in flight at a time,
//! no keepalive pings, no update handling. That is all the MCP tools need.

use futures_util::StreamExt;
use grammers_crypto::DequeBuffer;
use grammers_mtproto::authentication;
use grammers_mtproto::mtp::{self, Deserialization, Mtp};
use grammers_mtproto::transport::{self, Transport};
use grammers_mtproto::MsgId;
use grammers_tl_types::{self as tl, Deserializable, RemoteCall};
use worker::{WebSocket, WebsocketEvent};

pub enum Error {
    /// Telegram answered the RPC with an error (e.g. `AUTH_KEY_UNREGISTERED`).
    Rpc { code: i32, message: String },
    /// Anything that makes the connection unusable.
    Connection(String),
}

impl Error {
    pub fn is(&self, name: &str) -> bool {
        matches!(self, Error::Rpc { message, .. } if message == name)
    }

    /// For `*_MIGRATE_<N>` errors, the datacenter Telegram redirects us to.
    pub fn migrate_to_dc(&self) -> Option<u8> {
        match self {
            Error::Rpc { code: 303, message } => message
                .rsplit_once("_MIGRATE_")
                .and_then(|(_, n)| n.parse().ok()),
            _ => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Rpc { code, message } => write!(f, "rpc error {code}: {message}"),
            Error::Connection(m) => write!(f, "connection error: {m}"),
        }
    }
}

impl From<worker::Error> for Error {
    fn from(e: worker::Error) -> Self {
        Error::Connection(e.to_string())
    }
}

impl From<authentication::Error> for Error {
    fn from(e: authentication::Error) -> Self {
        Error::Connection(format!("auth key generation: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// WebSocket hostnames Telegram Web uses for each production datacenter.
pub fn dc_host(dc_id: u8) -> Option<&'static str> {
    Some(match dc_id {
        1 => "pluto.web.telegram.org",
        2 => "venus.web.telegram.org",
        3 => "aurora.web.telegram.org",
        4 => "vesta.web.telegram.org",
        5 => "flora.web.telegram.org",
        _ => return None,
    })
}

/// Open the WebSocket for a datacenter. The caller keeps the returned socket
/// alive for as long as it uses the [`Connection`] built from it.
pub async fn open_socket(host: &str) -> Result<WebSocket> {
    let url = format!("wss://{host}/apiws")
        .parse()
        .map_err(|e| Error::Connection(format!("bad ws url: {e}")))?;
    let ws = WebSocket::connect_with_protocols(url, Some(vec!["binary"])).await?;
    ws.accept()?;
    Ok(ws)
}

const MAX_ATTEMPTS: usize = 4;

pub struct Connection<'a, M: Mtp> {
    events: worker::EventStream<'a>,
    ws: &'a WebSocket,
    transport: transport::Obfuscated<transport::Intermediate>,
    mtp: M,
    read_buf: Vec<u8>,
}

/// Everything needed to reuse an authorization later.
#[derive(Clone, Copy)]
pub struct AuthKey {
    pub key: [u8; 256],
    pub time_offset: i32,
    pub salt: i64,
}

impl<'a> Connection<'a, mtp::Plain> {
    /// Unencrypted connection, only good for generating an auth key.
    pub fn plain(ws: &'a WebSocket) -> Result<Self> {
        Ok(Self {
            events: ws.events()?,
            ws,
            transport: transport::Obfuscated::new(transport::Intermediate::new()),
            mtp: mtp::Plain::new(),
            read_buf: Vec::new(),
        })
    }

    /// Run the Diffie-Hellman exchange and upgrade to an encrypted connection.
    pub async fn generate_auth_key(
        mut self,
    ) -> Result<(Connection<'a, mtp::Encrypted>, AuthKey)> {
        let (request, data) = authentication::step1()?;
        let response = self.invoke(&request).await?;
        let (request, data) = authentication::step2(data, response)?;
        let response = self.invoke(&request).await?;
        let (request, data) = authentication::step3(data, response)?;
        let response = self.invoke(&request).await?;
        let finished = authentication::create_key(data, response)?;

        let auth = AuthKey {
            key: finished.auth_key,
            time_offset: finished.time_offset,
            salt: finished.first_salt,
        };
        let conn = Connection {
            events: self.events,
            ws: self.ws,
            transport: self.transport,
            mtp: encrypted(&auth),
            read_buf: self.read_buf,
        };
        Ok((conn, auth))
    }
}

fn encrypted(auth: &AuthKey) -> mtp::Encrypted {
    mtp::Encrypted::build()
        .time_offset(auth.time_offset)
        .first_salt(auth.salt)
        .finish(auth.key)
}

impl<'a> Connection<'a, mtp::Encrypted> {
    pub fn encrypted(ws: &'a WebSocket, auth: &AuthKey) -> Result<Self> {
        Ok(Self {
            events: ws.events()?,
            ws,
            transport: transport::Obfuscated::new(transport::Intermediate::new()),
            mtp: encrypted(auth),
            read_buf: Vec::new(),
        })
    }
}

impl<'a, M: Mtp> Connection<'a, M> {
    pub async fn invoke<R: RemoteCall>(&mut self, request: &R) -> Result<R::Return> {
        let body = self.invoke_raw(request.to_bytes()).await?;
        R::Return::from_bytes(&body)
            .map_err(|e| Error::Connection(format!("bad rpc result body: {e}")))
    }

    async fn invoke_raw(&mut self, body: Vec<u8>) -> Result<Vec<u8>> {
        // A fresh session has no server salt and possibly a wrong clock offset;
        // Telegram answers with bad_server_salt / bad_msg_notification, the
        // Mtp layer corrects itself, and we resend. Bounded so a persistent
        // rejection cannot loop forever.
        for _ in 0..MAX_ATTEMPTS {
            let ids = self.send(&body)?;
            match self.wait_for(&ids).await? {
                Outcome::Result(bytes) => return Ok(bytes),
                Outcome::Retry => continue,
            }
        }
        Err(Error::Connection("request rejected repeatedly".into()))
    }

    fn send(&mut self, body: &[u8]) -> Result<Vec<MsgId>> {
        // Front capacity holds the transport header (4-byte length plus the
        // 64-byte obfuscation preamble on the first packet).
        let mut buf = DequeBuffer::with_capacity(body.len() + 64, 80);
        let msg_id = self
            .mtp
            .push(&mut buf, body)
            .ok_or_else(|| Error::Connection("request too large".into()))?;
        let mut ids = vec![msg_id];
        if let Some(container_id) = self.mtp.finalize(&mut buf) {
            if container_id != msg_id {
                ids.push(container_id);
            }
        }
        self.transport.pack(&mut buf);
        self.ws.send_with_bytes(buf.as_ref())?;
        Ok(ids)
    }

    async fn wait_for(&mut self, ids: &[MsgId]) -> Result<Outcome> {
        loop {
            let event = match self.events.next().await {
                Some(ev) => ev?,
                None => return Err(Error::Connection("socket closed".into())),
            };
            let bytes = match event {
                WebsocketEvent::Message(msg) => msg
                    .bytes()
                    .ok_or_else(|| Error::Connection("non-binary ws frame".into()))?,
                WebsocketEvent::Close(ev) => {
                    return Err(Error::Connection(format!(
                        "socket closed ({}: {})",
                        ev.code(),
                        ev.reason()
                    )))
                }
            };
            self.read_buf.extend_from_slice(&bytes);
            if let Some(outcome) = self.drain_read_buf(ids)? {
                return Ok(outcome);
            }
        }
    }

    /// Unpack every complete transport frame in the read buffer and look for
    /// the answer to `ids`. Unrelated messages (updates, acks) are dropped.
    fn drain_read_buf(&mut self, ids: &[MsgId]) -> Result<Option<Outcome>> {
        let mut outcome = None;
        let mut next = 0;
        while next != self.read_buf.len() {
            match self.transport.unpack(&mut self.read_buf[next..]) {
                Ok(offset) => {
                    let payload = &mut self.read_buf[next..][offset.data_range];
                    let results = self
                        .mtp
                        .deserialize(payload)
                        .map_err(|e| Error::Connection(format!("mtp: {e}")))?;
                    next += offset.next_offset;
                    for result in results {
                        match result {
                            Deserialization::RpcResult(r) if ids.contains(&r.msg_id) => {
                                outcome = Some(Outcome::Result(r.body));
                            }
                            Deserialization::RpcError(e) if ids.contains(&e.msg_id) => {
                                let tl::types::RpcError {
                                    error_code,
                                    error_message,
                                } = e.error;
                                return Err(Error::Rpc {
                                    code: error_code,
                                    message: error_message,
                                });
                            }
                            Deserialization::BadMessage(b) if ids.contains(&b.msg_id) => {
                                if b.retryable() {
                                    outcome = Some(Outcome::Retry);
                                } else {
                                    return Err(Error::Connection(format!(
                                        "bad message {}: {}",
                                        b.code,
                                        b.description()
                                    )));
                                }
                            }
                            Deserialization::Failure(f) if ids.contains(&f.msg_id) => {
                                return Err(Error::Connection(format!(
                                    "failed to deserialize response: {}",
                                    f.error
                                )));
                            }
                            _ => {}
                        }
                    }
                }
                Err(transport::Error::MissingBytes) => break,
                Err(e) => return Err(Error::Connection(format!("transport: {e}"))),
            }
        }
        self.read_buf.drain(..next);
        Ok(outcome)
    }
}

enum Outcome {
    Result(Vec<u8>),
    Retry,
}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn migrate_errors_name_the_dc() {
        let e = Error::Rpc {
            code: 303,
            message: "PHONE_MIGRATE_4".into(),
        };
        assert_eq!(e.migrate_to_dc(), Some(4));
        let e = Error::Rpc {
            code: 400,
            message: "PHONE_CODE_INVALID".into(),
        };
        assert_eq!(e.migrate_to_dc(), None);
        assert!(e.is("PHONE_CODE_INVALID"));
    }
}

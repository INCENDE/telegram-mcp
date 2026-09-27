//! The Durable Object that owns the Telegram authorization.
//!
//! One instance (named `account`) holds the auth key in its storage and
//! handles every Telegram call, so the key is never used from two places at
//! once (Telegram invalidates keys it sees on concurrent connections from
//! different IPs, and Workers egress from many IPs). The Worker in `lib.rs`
//! authenticates the caller and forwards the request here unchanged.

use worker::*;

use serde_json::Value;

use crate::html;
use crate::mcp;
use crate::session;
use crate::telegram::{self, Config, SignIn, Stage, Stored};
use crate::tools::{self, PeerCache};

const STORAGE_KEY: &str = "session";
const PEERS_KEY: &str = "peers";

#[durable_object(fetch)]
pub struct TelegramAccount {
    state: State,
    env: Env,
}

impl DurableObject for TelegramAccount {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path = req.path();
        let method = req.method();
        match (method, path.as_str()) {
            (Method::Get, "/login") => self.page(None).await,
            (Method::Post, "/login/phone") => self.phone(&mut req).await,
            (Method::Post, "/login/code") => self.code(&mut req).await,
            (Method::Post, "/login/password") => self.password(&mut req).await,
            (Method::Post, "/login/import") => self.import(&mut req).await,
            (Method::Post, "/logout") => self.logout().await,
            (Method::Get, "/spike") => self.spike().await,
            (Method::Get, "/diag") => self.diag(&req).await,
            (Method::Post, "/mcp") => self.mcp(&mut req).await,
            (Method::Get, "/mcp") | (Method::Delete, "/mcp") => {
                // Stateless server: no SSE stream to open, no session to end.
                Response::error("method not allowed", 405)
            }
            _ => Response::error("not found", 404),
        }
    }
}

impl TelegramAccount {
    fn config(&self) -> Result<Config> {
        Ok(Config {
            api_id: self
                .env
                .secret("TELEGRAM_API_ID")?
                .to_string()
                .parse()
                .map_err(|_| Error::RustError("TELEGRAM_API_ID is not an integer".into()))?,
            api_hash: self.env.secret("TELEGRAM_API_HASH")?.to_string(),
            ws_host: self.env.var("TELEGRAM_WS_HOST").ok().map(|v| v.to_string()),
        })
    }

    async fn load(&self) -> Result<Option<Stored>> {
        self.state.storage().get(STORAGE_KEY).await
    }

    async fn save(&self, stored: &Stored) -> Result<()> {
        self.state.storage().put(STORAGE_KEY, stored).await
    }

    /// Render the login page for the current stage, with an optional notice.
    async fn page(&self, notice: Option<(&str, bool)>) -> Result<Response> {
        let stage = self.load().await?.map(|s| s.stage);
        Response::from_html(html::login_page(stage.as_ref(), notice))
    }

    async fn phone(&self, req: &mut Request) -> Result<Response> {
        let phone = field(req, "phone").await?;
        let cfg = self.config()?;
        // Reuse an existing key when there is one (keeps the DC we ended up
        // on last time); otherwise start on DC 2, Telegram redirects if needed.
        let stored = match self.load().await? {
            Some(s) if s.stage == Stage::KeyOnly => s,
            Some(s) if matches!(s.stage, Stage::CodeSent { .. } | Stage::PasswordNeeded { .. }) => {
                s
            }
            _ => telegram::new_key(&cfg, 2).await.map_err(to_err)?.1,
        };
        match telegram::send_code(&cfg, stored, &phone).await {
            Ok(stored) => {
                self.save(&stored).await?;
                self.page(None).await
            }
            Err(e) => self.page(Some((&e.to_string(), true))).await,
        }
    }

    async fn code(&self, req: &mut Request) -> Result<Response> {
        let code = field(req, "code").await?;
        let cfg = self.config()?;
        let Some(stored) = self.load().await? else {
            return self.page(Some(("Start again: no code was requested.", true))).await;
        };
        match telegram::sign_in(&cfg, stored, &code).await {
            Ok(SignIn::Done(stored)) | Ok(SignIn::PasswordNeeded(stored)) => {
                self.save(&stored).await?;
                self.page(None).await
            }
            Err(e) => self.page(Some((&e.to_string(), true))).await,
        }
    }

    async fn password(&self, req: &mut Request) -> Result<Response> {
        let password = field(req, "password").await?;
        let cfg = self.config()?;
        let Some(stored) = self.load().await? else {
            return self.page(Some(("Start again: no password was requested.", true))).await;
        };
        match telegram::check_password(&cfg, stored, &password).await {
            Ok(stored) => {
                self.save(&stored).await?;
                self.page(None).await
            }
            Err(e) => self.page(Some((&e.to_string(), true))).await,
        }
    }

    async fn import(&self, req: &mut Request) -> Result<Response> {
        let string = field(req, "session").await?;
        match session::parse(&string) {
            Ok(s) => {
                let mut stored = telegram::import(s.dc_id, s.auth_key);
                // Prove the key works and learn whose it is before keeping it.
                let cfg = self.config()?;
                match telegram::whoami(&cfg, &stored).await {
                    Ok(stage) => {
                        stored.stage = stage;
                        self.save(&stored).await?;
                        self.page(None).await
                    }
                    Err(e) => self.page(Some((&e.to_string(), true))).await,
                }
            }
            Err(e) => self.page(Some((&e, true))).await,
        }
    }

    async fn logout(&self) -> Result<Response> {
        if let Some(stored) = self.load().await? {
            if matches!(stored.stage, Stage::Authorized { .. }) {
                // Best effort: even if Telegram is unreachable, forget the key.
                let _ = telegram::log_out(&self.config()?, &stored).await;
            }
        }
        self.state.storage().delete(STORAGE_KEY).await?;
        self.page(Some(("Logged out.", false))).await
    }

    /// `GET /diag[?host=...]`: transport check against the given host, or
    /// against every production datacenter when none is given.
    async fn diag(&self, req: &Request) -> Result<Response> {
        let url = req.url()?;
        let hosts: Vec<String> = match url.query_pairs().find(|(k, _)| k == "host") {
            // Only Telegram's own hosts: this endpoint must not become a way
            // to make the Worker open connections to arbitrary servers.
            Some((_, h)) if h.ends_with(".web.telegram.org") && !h.contains('/') => {
                vec![h.to_string()]
            }
            Some(_) => return Response::error("host must be a *.web.telegram.org name", 400),
            None => (1..=5)
                .filter_map(crate::mtproto::dc_host)
                .map(str::to_string)
                .collect(),
        };
        let mut out = Vec::new();
        for h in hosts {
            out.push(telegram::diag(&h).await);
        }
        Response::from_json(&out)
    }

    async fn spike(&self) -> Result<Response> {
        let Some(stored) = self.load().await? else {
            return Response::error("not logged in: open /login first", 409);
        };
        if !matches!(stored.stage, Stage::Authorized { .. }) {
            return Response::error("login not finished: open /login", 409);
        }
        let t0 = js_sys::Date::now();
        match telegram::dialogs(&self.config()?, &stored, 20).await {
            Ok(dialogs) => Response::from_json(&serde_json::json!({
                "dc": stored.dc_id,
                "dialogs": dialogs,
                "total_ms": js_sys::Date::now() - t0,
            })),
            Err(e) => Response::error(e.to_string(), 502),
        }
    }
}

impl TelegramAccount {
    async fn peers(&self) -> Result<PeerCache> {
        Ok(self.state.storage().get(PEERS_KEY).await?.unwrap_or_default())
    }

    async fn save_peers(&self, cache: &PeerCache) -> Result<()> {
        self.state.storage().put(PEERS_KEY, cache).await
    }

    /// Chats that `send_message` may write to, from the `ALLOWED_SEND_CHATS`
    /// variable (comma-separated ids). Unset means sending is disabled.
    fn allowed_send_chats(&self) -> Vec<i64> {
        self.env
            .var("ALLOWED_SEND_CHATS")
            .map(|v| v.to_string())
            .unwrap_or_default()
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    }

    async fn mcp(&self, req: &mut Request) -> Result<Response> {
        let body = req.text().await?;
        let (id, method, params) = match mcp::parse(&body) {
            mcp::Incoming::Request { id, method, params } => (id, method, params),
            mcp::Incoming::Notification => {
                return Ok(Response::empty()?.with_status(202));
            }
            mcp::Incoming::Invalid(why) => {
                return json_response(mcp::error(&Value::Null, mcp::INVALID_REQUEST, why));
            }
        };

        let reply = match method.as_str() {
            "initialize" => mcp::ok(&id, mcp::initialize_result()),
            "ping" => mcp::ok(&id, serde_json::json!({})),
            "tools/list" => mcp::ok(&id, mcp::tools()),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(Value::Null);
                match self.call_tool(name, &args).await {
                    Ok(text) => mcp::ok(&id, mcp::tool_result(text, false)),
                    Err(ToolError::Unknown) => {
                        mcp::error(&id, mcp::INVALID_PARAMS, format!("unknown tool '{name}'"))
                    }
                    Err(ToolError::Args(m)) => mcp::error(&id, mcp::INVALID_PARAMS, m),
                    // Tool-level failures go back as results so the model can react.
                    Err(ToolError::Failed(m)) => mcp::ok(&id, mcp::tool_result(m, true)),
                }
            }
            other => mcp::error(&id, mcp::METHOD_NOT_FOUND, format!("unknown method '{other}'")),
        };
        json_response(reply)
    }

    async fn call_tool(&self, name: &str, args: &Value) -> std::result::Result<String, ToolError> {
        let cfg = self.config().map_err(|e| ToolError::Failed(e.to_string()))?;
        let stored = match self.load().await.map_err(|e| ToolError::Failed(e.to_string()))? {
            Some(s) if matches!(s.stage, Stage::Authorized { .. }) => s,
            _ => return Err(ToolError::Failed("not logged in to Telegram: open /login".into())),
        };
        let mut cache = self.peers().await.map_err(|e| ToolError::Failed(e.to_string()))?;

        let result = match name {
            "list_chats" => {
                let limit = mcp::int_arg(args, "limit", 30).map_err(ToolError::Args)?;
                tools::list_chats(&cfg, &stored, &mut cache, limit as i32)
                    .await
                    .map(|chats| serde_json::to_string_pretty(&chats).unwrap_or_default())
            }
            "get_messages" => {
                let chat_id = mcp::int_arg(args, "chat_id", 0).map_err(ToolError::Args)?;
                if chat_id == 0 {
                    return Err(ToolError::Args("'chat_id' is required".into()));
                }
                let limit = mcp::int_arg(args, "limit", 30).map_err(ToolError::Args)?;
                let before = mcp::opt_int_arg(args, "before_id").map_err(ToolError::Args)?;
                tools::get_messages(
                    &cfg,
                    &stored,
                    &mut cache,
                    chat_id,
                    limit as i32,
                    before.map(|b| b as i32),
                )
                .await
                .map(|m| serde_json::to_string_pretty(&m).unwrap_or_default())
            }
            "search_messages" => {
                let query = mcp::str_arg(args, "query").map_err(ToolError::Args)?;
                let chat_id = mcp::opt_int_arg(args, "chat_id").map_err(ToolError::Args)?;
                let limit = mcp::int_arg(args, "limit", 20).map_err(ToolError::Args)?;
                tools::search_messages(&cfg, &stored, &mut cache, query, chat_id, limit as i32)
                    .await
                    .map(|m| serde_json::to_string_pretty(&m).unwrap_or_default())
            }
            "send_message" => {
                let chat_id = mcp::int_arg(args, "chat_id", 0).map_err(ToolError::Args)?;
                let text = mcp::str_arg(args, "text").map_err(ToolError::Args)?;
                let reply_to = mcp::opt_int_arg(args, "reply_to").map_err(ToolError::Args)?;
                let allowed = self.allowed_send_chats();
                if !allowed.contains(&chat_id) {
                    return Err(ToolError::Failed(format!(
                        "sending to chat {chat_id} is not allowed. Allowed chats: {}. \
                         The owner sets ALLOWED_SEND_CHATS on the Worker.",
                        if allowed.is_empty() {
                            "none".to_string()
                        } else {
                            allowed.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
                        }
                    )));
                }
                tools::send_message(
                    &cfg,
                    &stored,
                    &mut cache,
                    chat_id,
                    text,
                    reply_to.map(|r| r as i32),
                )
                .await
                .map(|sent| match sent.message_id {
                    Some(id) => format!("sent to {} (message id {id})", sent.chat),
                    None => format!("sent to {}", sent.chat),
                })
            }
            _ => return Err(ToolError::Unknown),
        };

        // Persist whatever the call learned about peers, even on failure.
        let _ = self.save_peers(&cache).await;
        result.map_err(|e| ToolError::Failed(e.to_string()))
    }
}

enum ToolError {
    Unknown,
    Args(String),
    Failed(String),
}

fn json_response(v: Value) -> Result<Response> {
    let mut resp = Response::from_json(&v)?;
    resp.headers_mut().set("content-type", "application/json")?;
    Ok(resp)
}

async fn field(req: &mut Request, name: &str) -> Result<String> {
    match req.form_data().await?.get(name) {
        Some(FormEntry::Field(v)) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => Err(Error::RustError(format!("missing form field '{name}'"))),
    }
}

fn to_err(e: crate::mtproto::Error) -> Error {
    Error::RustError(e.to_string())
}

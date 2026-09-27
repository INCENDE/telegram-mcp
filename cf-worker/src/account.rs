//! The Durable Object that owns the Telegram authorization.
//!
//! One instance (named `account`) holds the auth key in its storage and
//! handles every Telegram call, so the key is never used from two places at
//! once (Telegram invalidates keys it sees on concurrent connections from
//! different IPs, and Workers egress from many IPs). The Worker in `lib.rs`
//! authenticates the caller and forwards the request here unchanged.

use worker::*;

use crate::html;
use crate::session;
use crate::telegram::{self, Config, SignIn, Stage, Stored};

const STORAGE_KEY: &str = "session";

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
            Some((_, h)) => vec![h.to_string()],
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

async fn field(req: &mut Request, name: &str) -> Result<String> {
    match req.form_data().await?.get(name) {
        Some(FormEntry::Field(v)) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => Err(Error::RustError(format!("missing form field '{name}'"))),
    }
}

fn to_err(e: crate::mtproto::Error) -> Error {
    Error::RustError(e.to_string())
}

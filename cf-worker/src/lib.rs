//! Telegram as a user account, from a Cloudflare Worker.
//!
//! This Worker does two things: it verifies the Cloudflare Access assertion
//! on the request (see `access.rs`), and it forwards the request to the
//! single Durable Object (`account.rs`) that holds the Telegram
//! authorization and talks MTProto.
//!
//! Routes (all behind Access):
//! - `GET /login` and its `POST /login/*` forms: log the account in from a
//!   browser, so no session string ever has to leave Cloudflare.
//! - `POST /logout`: revoke the authorization and forget the key.
//! - `GET /spike`: connection test, returns the first 20 dialogs and timing.

mod access;
mod account;
mod html;
mod mtproto;
mod session;
mod telegram;

use worker::*;

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let team_domain = env.var("ACCESS_TEAM_DOMAIN")?.to_string();
    let aud = env.var("ACCESS_AUD")?.to_string();
    match access::verify(&req, &team_domain, &aud).await? {
        Ok(claims) => console_log!("{} {} by {}", req.method(), req.path(), claims.who()),
        Err(access::Rejection::Missing) => {
            return Response::error("no Cloudflare Access assertion", 401)
        }
        Err(access::Rejection::Invalid(why)) => {
            console_warn!("rejected access assertion: {why}");
            return Response::error("invalid Cloudflare Access assertion", 403);
        }
    }

    env.durable_object("TELEGRAM_ACCOUNT")?
        .id_from_name("account")?
        .get_stub()?
        .fetch_with_request(req)
        .await
}

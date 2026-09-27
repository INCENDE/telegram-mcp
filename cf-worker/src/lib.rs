//! Telegram as a user account, from a Cloudflare Worker.
//!
//! This Worker does two things: it checks that the caller knows
//! `ADMIN_TOKEN`, and it forwards the request to the single Durable Object
//! (`account.rs`) that holds the Telegram authorization and talks MTProto.
//!
//! Routes (all behind the token):
//! - `GET /login` and its `POST /login/*` forms: log the account in from a
//!   browser, so no session string ever has to leave Cloudflare.
//! - `POST /logout`: revoke the authorization and forget the key.
//! - `GET /spike`: connection test, returns the first 20 dialogs and timing.

mod account;
mod html;
mod mtproto;
mod session;
mod telegram;

use worker::*;

const COOKIE: &str = "admin";

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let token = env.secret("ADMIN_TOKEN")?.to_string();
    if token.len() < 16 {
        return Response::error("ADMIN_TOKEN secret is missing or too short", 500);
    }

    let presented = presented_token(&req)?;
    let via_query = matches!(&presented, Some((_, Via::Query)));
    if presented.map(|(t, _)| t) != Some(token.clone()) {
        return Response::error("unauthorized", 401);
    }

    let stub = env
        .durable_object("TELEGRAM_ACCOUNT")?
        .id_from_name("account")?
        .get_stub()?;
    let mut resp = stub.fetch_with_request(req).await?;

    // A token given once in the URL becomes a cookie so the forms work
    // without carrying it around.
    if via_query {
        resp.headers_mut().set(
            "set-cookie",
            &format!("{COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400"),
        )?;
    }
    Ok(resp)
}

enum Via {
    Header,
    Cookie,
    Query,
}

fn presented_token(req: &Request) -> Result<Option<(String, Via)>> {
    if let Some(h) = req.headers().get("authorization")? {
        if let Some(t) = h.strip_prefix("Bearer ") {
            return Ok(Some((t.trim().to_string(), Via::Header)));
        }
    }
    if let Some(cookies) = req.headers().get("cookie")? {
        for part in cookies.split(';') {
            if let Some(v) = part.trim().strip_prefix(&format!("{COOKIE}=")) {
                return Ok(Some((v.to_string(), Via::Cookie)));
            }
        }
    }
    let url = req.url()?;
    if let Some((_, v)) = url.query_pairs().find(|(k, _)| k == "token") {
        return Ok(Some((v.to_string(), Via::Query)));
    }
    Ok(None)
}

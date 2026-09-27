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
//! - `POST /mcp`: the MCP server (streamable HTTP, stateless JSON-RPC).

mod access;
mod account;
mod html;
mod mcp;
mod mtproto;
mod session;
mod telegram;
mod tools;

use worker::*;

/// The only hostname this Worker is served on. Browser-originated POSTs
/// must come from a page on it (defense in depth on top of Access's
/// SameSite cookie), and the Origin check below enforces that.
const SELF_ORIGIN: &str = "https://telegram.incende.fyi";

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();
    harden(handle(req, env).await?)
}

async fn handle(req: Request, env: Env) -> Result<Response> {
    let team_domain = env.var("ACCESS_TEAM_DOMAIN")?.to_string();
    let aud = env.var("ACCESS_AUD")?.to_string();
    match access::verify(&req, &team_domain, &aud).await? {
        // Log the route only: no identity, no query string, no bodies.
        Ok(_) => console_log!("{} {}", req.method(), req.path()),
        Err(access::Rejection::Missing) => {
            return Response::error("no Cloudflare Access assertion", 401)
        }
        Err(access::Rejection::Invalid(why)) => {
            console_warn!("rejected access assertion: {why}");
            return Response::error("invalid Cloudflare Access assertion", 403);
        }
    }

    if !same_origin_or_non_browser(&req)? {
        return Response::error("cross-origin request refused", 403);
    }

    env.durable_object("TELEGRAM_ACCOUNT")?
        .id_from_name("account")?
        .get_stub()?
        .fetch_with_request(req)
        .await
}

/// Browsers attach `Origin` (and `Sec-Fetch-Site`) to cross-site requests;
/// MCP clients and curl send neither. Refuse anything a browser sends from a
/// page that is not ours, so a malicious site cannot drive the forms or the
/// MCP endpoint with the owner's Access cookie.
fn same_origin_or_non_browser(req: &Request) -> Result<bool> {
    if let Some(site) = req.headers().get("sec-fetch-site")? {
        if site == "cross-site" {
            return Ok(false);
        }
    }
    match req.headers().get("origin")? {
        None => Ok(true),
        Some(o) if o == "null" => Ok(false),
        Some(o) => Ok(o.eq_ignore_ascii_case(SELF_ORIGIN)),
    }
}

/// Headers every response carries: nothing cached (responses contain
/// private chat content), no framing, no referrer leakage, and a CSP that
/// allows only this Worker's own inline styles and same-origin forms.
fn harden(mut resp: Response) -> Result<Response> {
    let h = resp.headers_mut();
    h.set("cache-control", "no-store")?;
    h.set("x-content-type-options", "nosniff")?;
    h.set("x-frame-options", "DENY")?;
    h.set("referrer-policy", "no-referrer")?;
    h.set("x-robots-tag", "noindex, nofollow")?;
    h.set(
        "content-security-policy",
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    )?;
    h.set(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    )?;
    Ok(resp)
}

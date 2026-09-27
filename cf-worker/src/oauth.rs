//! OAuth 2.1 authorization server for the MCP endpoint, as the MCP
//! authorization spec expects: protected-resource metadata, server metadata,
//! dynamic client registration, authorization code + PKCE, refresh tokens.
//!
//! The human step is not reimplemented: `/oauth/authorize` sits behind
//! Cloudflare Access, so reaching the consent page already means the owner
//! passed the one-time PIN. Approving issues a code; the token endpoint and
//! `/mcp` are Access-bypassed and guarded by the tokens minted here, which
//! are 256-bit random values stored only as SHA-256 hashes.

// Not yet routed from the Worker: enabling it requires an Access bypass on the
// public OAuth paths, which is pending the owner's decision (see the PR).
#![allow(dead_code)]

use std::collections::HashMap;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use worker::{js_sys, Headers, Request, Response, Result, Storage, Url};

use crate::html;

pub const ISSUER: &str = "https://telegram.incende.fyi";
pub const RESOURCE: &str = "https://telegram.incende.fyi/mcp";
const SCOPE: &str = "telegram";

const CODE_TTL_MS: f64 = 5.0 * 60.0 * 1000.0;
const ACCESS_TTL_MS: f64 = 7.0 * 24.0 * 3600.0 * 1000.0;
const REFRESH_TTL_MS: f64 = 90.0 * 24.0 * 3600.0 * 1000.0;

const CLIENTS_KEY: &str = "oauth_clients";
const CODES_KEY: &str = "oauth_codes";
const TOKENS_KEY: &str = "oauth_tokens";

#[derive(Serialize, Deserialize, Clone)]
pub struct Client {
    pub name: String,
    pub redirect_uris: Vec<String>,
    /// SHA-256 of the client secret, for confidential clients; none for
    /// public clients (`token_endpoint_auth_method: none`).
    pub secret_hash: Option<String>,
    pub created_ms: f64,
}

#[derive(Serialize, Deserialize, Clone)]
struct Code {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    expires_ms: f64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
enum Kind {
    Access,
    Refresh,
}

#[derive(Serialize, Deserialize, Clone)]
struct Token {
    client_id: String,
    kind: Kind,
    expires_ms: f64,
    /// Ties an access token to the refresh token issued with it, so rotating
    /// or revoking one removes the other.
    grant: String,
}

type Clients = HashMap<String, Client>;
type Codes = HashMap<String, Code>;
type Tokens = HashMap<String, Token>;

fn now_ms() -> f64 {
    js_sys::Date::now()
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("randomness");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hash(s: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(s.as_bytes()))
}

fn json_with_status(v: Value, status: u16) -> Result<Response> {
    Ok(Response::from_json(&v)?.with_status(status))
}

fn oauth_error(error: &str, description: &str, status: u16) -> Result<Response> {
    json_with_status(
        json!({ "error": error, "error_description": description }),
        status,
    )
}

// ---------------------------------------------------------------- metadata

pub fn protected_resource_metadata() -> Result<Response> {
    Response::from_json(&json!({
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "scopes_supported": [SCOPE],
        "bearer_methods_supported": ["header"],
        "resource_name": "Telegram MCP",
    }))
}

pub fn authorization_server_metadata() -> Result<Response> {
    Response::from_json(&json!({
        "issuer": ISSUER,
        "authorization_endpoint": format!("{ISSUER}/oauth/authorize"),
        "token_endpoint": format!("{ISSUER}/oauth/token"),
        "registration_endpoint": format!("{ISSUER}/oauth/register"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "scopes_supported": [SCOPE],
        "resource_indicators_supported": true,
    }))
}

/// The 401 an unauthenticated `/mcp` request gets, pointing at the metadata.
pub fn unauthorized(detail: &str) -> Result<Response> {
    let headers = Headers::new();
    headers.set(
        "www-authenticate",
        &format!(
            "Bearer realm=\"telegram-mcp\", error=\"invalid_token\", error_description=\"{detail}\", \
             resource_metadata=\"{ISSUER}/.well-known/oauth-protected-resource\""
        ),
    )?;
    Ok(Response::error(detail, 401)?.with_headers(headers))
}

// ------------------------------------------------------------ registration

fn redirect_uri_allowed(uri: &str) -> bool {
    let Ok(u) = Url::parse(uri) else { return false };
    match u.scheme() {
        "https" => u.host_str().is_some(),
        // Native/CLI clients (Claude Code, MCP Inspector) listen on loopback.
        "http" => matches!(u.host_str(), Some("localhost") | Some("127.0.0.1") | Some("[::1]")),
        _ => false,
    }
}

/// RFC 7591 dynamic registration. Open by design: registering only names a
/// client; nothing is granted until the owner approves it on the consent
/// page, which shows the client name and redirect host.
pub async fn register(storage: &Storage, req: &mut Request) -> Result<Response> {
    let body: Value = match req.json().await {
        Ok(v) => v,
        Err(_) => return oauth_error("invalid_client_metadata", "body must be JSON", 400),
    };
    let redirect_uris: Vec<String> = body
        .get("redirect_uris")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    if redirect_uris.is_empty() || !redirect_uris.iter().all(|u| redirect_uri_allowed(u)) {
        return oauth_error(
            "invalid_redirect_uri",
            "redirect_uris must be https URLs or http://localhost",
            400,
        );
    }
    let name = body
        .get("client_name")
        .and_then(Value::as_str)
        .unwrap_or("Unnamed client")
        .chars()
        .take(80)
        .collect::<String>();
    let auth_method = body
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .unwrap_or("client_secret_basic");
    let secret = (auth_method != "none").then(random_token);

    let client_id = random_token();
    let mut clients: Clients = storage.get(CLIENTS_KEY).await?.unwrap_or_default();
    clients.insert(
        client_id.clone(),
        Client {
            name: name.clone(),
            redirect_uris: redirect_uris.clone(),
            secret_hash: secret.as_deref().map(hash),
            created_ms: now_ms(),
        },
    );
    storage.put(CLIENTS_KEY, &clients).await?;

    let mut out = json!({
        "client_id": client_id,
        "client_id_issued_at": (now_ms() / 1000.0) as u64,
        "client_name": name,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": if secret.is_some() { auth_method } else { "none" },
        "scope": SCOPE,
    });
    if let Some(s) = secret {
        out["client_secret"] = Value::String(s);
        out["client_secret_expires_at"] = Value::from(0);
    }
    json_with_status(out, 201)
}

// ------------------------------------------------------------ authorization

pub struct AuthorizeParams {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub code_challenge: String,
}

fn query(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.to_string())
}

/// `GET /oauth/authorize`: validate the request and show the consent page.
/// Reached only through Access, so the viewer is the owner.
pub async fn authorize(storage: &Storage, req: &Request) -> Result<Response> {
    let url = req.url()?;
    let get = |k: &str| query(&url, k);

    let Some(client_id) = get("client_id") else {
        return Response::error("missing client_id", 400);
    };
    let clients: Clients = storage.get(CLIENTS_KEY).await?.unwrap_or_default();
    let Some(client) = clients.get(&client_id) else {
        return Response::error("unknown client_id", 400);
    };
    let Some(redirect_uri) = get("redirect_uri") else {
        return Response::error("missing redirect_uri", 400);
    };
    if !client.redirect_uris.iter().any(|u| u == &redirect_uri) {
        // Never redirect to an unregistered URI, even to report the error.
        return Response::error("redirect_uri is not registered for this client", 400);
    }

    let deny = |error: &str, desc: &str| -> Result<Response> {
        let mut back = Url::parse(&redirect_uri).map_err(|e| worker::Error::RustError(e.to_string()))?;
        back.query_pairs_mut()
            .append_pair("error", error)
            .append_pair("error_description", desc);
        if let Some(s) = get("state") {
            back.query_pairs_mut().append_pair("state", &s);
        }
        Response::redirect(back)
    };

    if get("response_type").as_deref() != Some("code") {
        return deny("unsupported_response_type", "only response_type=code is supported");
    }
    if get("code_challenge_method").as_deref() != Some("S256") {
        return deny("invalid_request", "PKCE with S256 is required");
    }
    let Some(code_challenge) = get("code_challenge").filter(|c| !c.is_empty()) else {
        return deny("invalid_request", "code_challenge is required");
    };
    if let Some(r) = get("resource") {
        if r != RESOURCE {
            return deny("invalid_target", "unknown resource");
        }
    }

    let params = AuthorizeParams {
        client_id,
        redirect_uri,
        state: get("state"),
        code_challenge,
    };
    Response::from_html(html::consent_page(&client.name, &params))
}

/// `POST /oauth/approve` from the consent form: mint the code and redirect.
pub async fn approve(storage: &Storage, req: &mut Request) -> Result<Response> {
    let form = req.form_data().await?;
    let field = |k: &str| match form.get(k) {
        Some(worker::FormEntry::Field(v)) => Some(v),
        _ => None,
    };
    let (Some(client_id), Some(redirect_uri), Some(code_challenge)) =
        (field("client_id"), field("redirect_uri"), field("code_challenge"))
    else {
        return Response::error("incomplete consent form", 400);
    };
    let clients: Clients = storage.get(CLIENTS_KEY).await?.unwrap_or_default();
    let Some(client) = clients.get(&client_id) else {
        return Response::error("unknown client_id", 400);
    };
    if !client.redirect_uris.iter().any(|u| u == &redirect_uri) {
        return Response::error("redirect_uri is not registered for this client", 400);
    }

    let mut back = Url::parse(&redirect_uri).map_err(|e| worker::Error::RustError(e.to_string()))?;
    if let Some(s) = field("state") {
        back.query_pairs_mut().append_pair("state", &s);
    }

    if field("decision").as_deref() != Some("allow") {
        back.query_pairs_mut()
            .append_pair("error", "access_denied")
            .append_pair("error_description", "the owner declined");
        return Response::redirect(back);
    }

    let code = random_token();
    let mut codes: Codes = storage.get(CODES_KEY).await?.unwrap_or_default();
    let now = now_ms();
    codes.retain(|_, c| c.expires_ms > now);
    codes.insert(
        hash(&code),
        Code {
            client_id,
            redirect_uri,
            code_challenge,
            expires_ms: now + CODE_TTL_MS,
        },
    );
    storage.put(CODES_KEY, &codes).await?;

    back.query_pairs_mut().append_pair("code", &code);
    Response::redirect(back)
}

// -------------------------------------------------------------------- token

fn pkce_ok(verifier: &str, challenge: &str) -> bool {
    hash(verifier) == challenge
}

async fn client_authenticated(
    clients: &Clients,
    client_id: &str,
    presented_secret: Option<&str>,
) -> bool {
    match clients.get(client_id) {
        None => false,
        Some(Client { secret_hash: None, .. }) => true,
        Some(Client {
            secret_hash: Some(h),
            ..
        }) => presented_secret.map(hash).as_deref() == Some(h.as_str()),
    }
}

/// `POST /oauth/token`: authorization_code (with PKCE) or refresh_token.
pub async fn token(storage: &Storage, req: &mut Request) -> Result<Response> {
    // Basic auth is one of the allowed client authentication methods.
    let basic = req
        .headers()
        .get("authorization")?
        .and_then(|h| h.strip_prefix("Basic ").map(str::to_string))
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| s.split_once(':').map(|(i, s)| (i.to_string(), s.to_string())));

    let form = req.form_data().await?;
    let field = |k: &str| match form.get(k) {
        Some(worker::FormEntry::Field(v)) => Some(v),
        _ => None,
    };
    let client_id = field("client_id").or_else(|| basic.as_ref().map(|(i, _)| i.clone()));
    let client_secret = field("client_secret").or_else(|| basic.as_ref().map(|(_, s)| s.clone()));
    let Some(client_id) = client_id else {
        return oauth_error("invalid_client", "client_id is required", 401);
    };
    let clients: Clients = storage.get(CLIENTS_KEY).await?.unwrap_or_default();
    if !client_authenticated(&clients, &client_id, client_secret.as_deref()).await {
        return oauth_error("invalid_client", "unknown client or bad secret", 401);
    }

    let mut tokens: Tokens = storage.get(TOKENS_KEY).await?.unwrap_or_default();
    let now = now_ms();
    tokens.retain(|_, t| t.expires_ms > now);

    let grant = match field("grant_type").as_deref() {
        Some("authorization_code") => {
            let (Some(code), Some(verifier)) = (field("code"), field("code_verifier")) else {
                return oauth_error("invalid_request", "code and code_verifier are required", 400);
            };
            let mut codes: Codes = storage.get(CODES_KEY).await?.unwrap_or_default();
            let Some(stored) = codes.remove(&hash(&code)) else {
                return oauth_error("invalid_grant", "unknown or already used code", 400);
            };
            // Single use, whatever happens next.
            storage.put(CODES_KEY, &codes).await?;
            if stored.expires_ms < now
                || stored.client_id != client_id
                || field("redirect_uri").is_some_and(|r| r != stored.redirect_uri)
                || !pkce_ok(&verifier, &stored.code_challenge)
            {
                return oauth_error("invalid_grant", "code does not match this request", 400);
            }
            random_token()
        }
        Some("refresh_token") => {
            let Some(refresh) = field("refresh_token") else {
                return oauth_error("invalid_request", "refresh_token is required", 400);
            };
            let Some(old) = tokens.remove(&hash(&refresh)) else {
                return oauth_error("invalid_grant", "unknown or expired refresh token", 400);
            };
            if old.kind != Kind::Refresh || old.client_id != client_id {
                return oauth_error("invalid_grant", "refresh token does not belong to this client", 400);
            }
            // Rotate: everything from the old grant goes away.
            tokens.retain(|_, t| t.grant != old.grant);
            random_token()
        }
        _ => return oauth_error("unsupported_grant_type", "use authorization_code or refresh_token", 400),
    };

    let access = random_token();
    let refresh = random_token();
    tokens.insert(
        hash(&access),
        Token {
            client_id: client_id.clone(),
            kind: Kind::Access,
            expires_ms: now + ACCESS_TTL_MS,
            grant: grant.clone(),
        },
    );
    tokens.insert(
        hash(&refresh),
        Token {
            client_id,
            kind: Kind::Refresh,
            expires_ms: now + REFRESH_TTL_MS,
            grant,
        },
    );
    storage.put(TOKENS_KEY, &tokens).await?;

    let headers = Headers::new();
    headers.set("cache-control", "no-store")?;
    headers.set("pragma", "no-cache")?;
    Ok(Response::from_json(&json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": (ACCESS_TTL_MS / 1000.0) as u64,
        "refresh_token": refresh,
        "scope": SCOPE,
    }))?
    .with_headers(headers))
}

// ------------------------------------------------------------ verification

/// Check the bearer token on an `/mcp` request. Returns the client id.
pub async fn verify_bearer(storage: &Storage, req: &Request) -> Result<std::result::Result<String, &'static str>> {
    let Some(h) = req.headers().get("authorization")? else {
        return Ok(Err("missing bearer token"));
    };
    let Some(presented) = h.strip_prefix("Bearer ") else {
        return Ok(Err("authorization must be a bearer token"));
    };
    let tokens: Tokens = storage.get(TOKENS_KEY).await?.unwrap_or_default();
    match tokens.get(&hash(presented.trim())) {
        Some(t) if t.kind == Kind::Access && t.expires_ms > now_ms() => Ok(Ok(t.client_id.clone())),
        Some(_) => Ok(Err("token expired")),
        None => Ok(Err("unknown token")),
    }
}

// ------------------------------------------------------------- management

pub struct Connection {
    pub client_id: String,
    pub name: String,
    pub expires_ms: f64,
}

/// Clients that currently hold a live token, for the login page.
pub async fn connections(storage: &Storage) -> Result<Vec<Connection>> {
    let clients: Clients = storage.get(CLIENTS_KEY).await?.unwrap_or_default();
    let tokens: Tokens = storage.get(TOKENS_KEY).await?.unwrap_or_default();
    let now = now_ms();
    let mut by_client: HashMap<String, f64> = HashMap::new();
    for t in tokens.values() {
        if t.kind == Kind::Refresh && t.expires_ms > now {
            let e = by_client.entry(t.client_id.clone()).or_insert(0.0);
            *e = e.max(t.expires_ms);
        }
    }
    let mut out: Vec<_> = by_client
        .into_iter()
        .map(|(client_id, expires_ms)| Connection {
            name: clients
                .get(&client_id)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| "unknown client".into()),
            client_id,
            expires_ms,
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Revoke every token of one client (or all clients when `client_id` is
/// `None`) and forget its registration.
pub async fn revoke(storage: &Storage, client_id: Option<&str>) -> Result<()> {
    let mut tokens: Tokens = storage.get(TOKENS_KEY).await?.unwrap_or_default();
    let mut clients: Clients = storage.get(CLIENTS_KEY).await?.unwrap_or_default();
    match client_id {
        Some(id) => {
            tokens.retain(|_, t| t.client_id != id);
            clients.remove(id);
        }
        None => {
            tokens.clear();
            clients.clear();
        }
    }
    storage.put(TOKENS_KEY, &tokens).await?;
    storage.put(CLIENTS_KEY, &clients).await?;
    storage.delete(CODES_KEY).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_matches_rfc_example() {
        // RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(pkce_ok(verifier, challenge));
        assert!(!pkce_ok("wrong", challenge));
    }

    #[test]
    fn redirect_uris_are_limited_to_https_and_loopback() {
        assert!(redirect_uri_allowed("https://claude.ai/api/mcp/auth_callback"));
        assert!(redirect_uri_allowed("http://localhost:3456/callback"));
        assert!(redirect_uri_allowed("http://127.0.0.1:8080/cb"));
        assert!(!redirect_uri_allowed("http://evil.example/cb"));
        assert!(!redirect_uri_allowed("javascript:alert(1)"));
        assert!(!redirect_uri_allowed("not a url"));
    }
}

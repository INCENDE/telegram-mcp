//! Cloudflare Access JWT verification.
//!
//! Access sits in front of `telegram.incende.fyi` and only lets through
//! requests from an identity the application's policies allow (the owner via
//! one-time PIN, or an MCP client presenting a service token). Every request
//! it forwards carries a signed JWT in `Cf-Access-Jwt-Assertion`. We verify
//! it here rather than trusting the header, so that a request that somehow
//! reaches the Worker without passing Access (a misconfigured route, a
//! forgotten preview URL) is still rejected.

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use worker::{Fetch, Request, Result, Url};

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Deserialize)]
pub struct Claims {
    /// Present for human logins.
    #[serde(default)]
    pub email: Option<String>,
    /// Present for service tokens.
    #[serde(default)]
    pub common_name: Option<String>,
}

impl Claims {
    pub fn who(&self) -> String {
        self.email
            .clone()
            .or_else(|| self.common_name.clone())
            .unwrap_or_else(|| "unknown".into())
    }
}

pub enum Rejection {
    Missing,
    Invalid(String),
}

/// Verify the Access assertion on `req` against `team_domain` and `aud`.
pub async fn verify(
    req: &Request,
    team_domain: &str,
    aud: &str,
) -> Result<std::result::Result<Claims, Rejection>> {
    let Some(token) = assertion(req)? else {
        return Ok(Err(Rejection::Missing));
    };

    let kid = match decode_header(&token) {
        Ok(h) => h.kid.unwrap_or_default(),
        Err(e) => return Ok(Err(Rejection::Invalid(format!("bad header: {e}")))),
    };

    let jwks = fetch_jwks(team_domain).await?;
    let Some(jwk) = jwks.keys.iter().find(|k| k.kid == kid) else {
        return Ok(Err(Rejection::Invalid("unknown signing key".into())));
    };
    let key = match DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
        Ok(k) => k,
        Err(e) => return Ok(Err(Rejection::Invalid(format!("bad jwk: {e}")))),
    };

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[aud]);
    validation.set_issuer(&[format!("https://{team_domain}")]);
    validation.set_required_spec_claims(&["exp", "aud", "iss"]);

    match decode::<Claims>(&token, &key, &validation) {
        Ok(data) => Ok(Ok(data.claims)),
        Err(e) => Ok(Err(Rejection::Invalid(e.to_string()))),
    }
}

fn assertion(req: &Request) -> Result<Option<String>> {
    if let Some(h) = req.headers().get("cf-access-jwt-assertion")? {
        if !h.is_empty() {
            return Ok(Some(h));
        }
    }
    // Browser requests also carry it as a cookie; the header is what Access
    // adds on the way in, so it is normally present. Kept for completeness.
    if let Some(cookies) = req.headers().get("cookie")? {
        for part in cookies.split(';') {
            if let Some(v) = part.trim().strip_prefix("CF_Authorization=") {
                return Ok(Some(v.to_string()));
            }
        }
    }
    Ok(None)
}

async fn fetch_jwks(team_domain: &str) -> Result<Jwks> {
    let url: Url = format!("https://{team_domain}/cdn-cgi/access/certs").parse()?;
    let mut resp = Fetch::Url(url).send().await?;
    resp.json::<Jwks>().await
}

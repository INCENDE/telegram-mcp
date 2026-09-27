//! The login page. Plain HTML forms, no JavaScript, so it works from a phone.

use crate::oauth::{AuthorizeParams, Connection};
use crate::telegram::Stage;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn login_page(
    stage: Option<&Stage>,
    notice: Option<(&str, bool)>,
    connections: &[Connection],
) -> String {
    let notice = match notice {
        Some((text, is_error)) => format!(
            r#"<p class="notice {}">{}</p>"#,
            if is_error { "error" } else { "ok" },
            esc(text)
        ),
        None => String::new(),
    };

    let body = match stage {
        None | Some(Stage::KeyOnly) => r#"
            <h1>Log in to Telegram</h1>
            <p>Enter the phone number of the account, with country code.</p>
            <form method="post" action="/login/phone">
              <input name="phone" type="tel" placeholder="+65 8123 4567" autocomplete="tel" required autofocus>
              <button>Send code</button>
            </form>
            <details>
              <summary>Have a Telethon session string instead?</summary>
              <form method="post" action="/login/import">
                <input name="session" type="password" placeholder="1AZ…" required>
                <button>Import</button>
              </form>
            </details>"#
            .to_string(),
        Some(Stage::CodeSent { phone, via, .. }) => format!(
            r#"
            <h1>Enter the code</h1>
            <p>Telegram sent a code to <b>{}</b> via {}.</p>
            <form method="post" action="/login/code">
              <input name="code" inputmode="numeric" autocomplete="one-time-code" placeholder="12345" required autofocus>
              <button>Sign in</button>
            </form>
            <form method="post" action="/logout"><button class="link">Start over</button></form>"#,
            esc(phone),
            esc(via)
        ),
        Some(Stage::PasswordNeeded { hint, .. }) => format!(
            r#"
            <h1>Two-step verification</h1>
            <p>This account has a cloud password.{}</p>
            <form method="post" action="/login/password">
              <input name="password" type="password" autocomplete="current-password" required autofocus>
              <button>Sign in</button>
            </form>
            <form method="post" action="/logout"><button class="link">Start over</button></form>"#,
            if hint.is_empty() {
                String::new()
            } else {
                format!(" Hint: <i>{}</i>", esc(hint))
            }
        ),
        Some(Stage::Authorized { name, user_id }) => format!(
            r#"
            <h1>Logged in</h1>
            <p>Connected as <b>{}</b> (id {}).</p>
            <p><a href="/spike">Run the connection test</a> (returns JSON).</p>
            <h2>Connect an MCP client</h2>
            <p>Add <code>https://telegram.incende.fyi/mcp</code> as a custom connector
            (Claude app: Settings → Connectors → Add custom connector) or with
            <code>claude mcp add --transport http telegram https://telegram.incende.fyi/mcp</code>.
            The client will send you here to approve it.</p>
            <p>Tools: list_chats, get_messages, search_messages, send_message
            (sending only to chats listed in the Worker's <code>ALLOWED_SEND_CHATS</code> variable).</p>
            {connections}
            <form method="post" action="/logout"><button class="danger">Log out and forget the key</button></form>"#,
            esc(name),
            user_id,
            connections = connections_list(connections),
        ),
    };

    shell(&format!("{notice}\n{body}"))
}

fn shell(body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>Telegram MCP</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 26rem; margin: 3rem auto; padding: 0 1rem; }}
  h1 {{ font-size: 1.4rem; }}
  input {{ display: block; width: 100%; box-sizing: border-box; font: inherit; padding: .6rem; margin: .5rem 0; }}
  button {{ font: inherit; padding: .6rem 1rem; cursor: pointer; }}
  button.link {{ background: none; border: none; padding: 0; text-decoration: underline; color: inherit; margin-top: 1rem; }}
  button.danger {{ color: #b00020; }}
  form.inline {{ display: inline; margin-left: .5rem; }}
  ul {{ padding-left: 1.2rem; }}
  details {{ margin-top: 2rem; }}
  h2 {{ font-size: 1.1rem; margin-top: 2rem; }}
  pre, code {{ font-size: .85em; }}
  pre {{ overflow-x: auto; padding: .6rem; background: rgba(127,127,127,.12); border-radius: 4px; }}
  .notice {{ padding: .6rem .8rem; border-radius: 4px; }}
  .notice.error {{ background: #fde8e8; color: #7a0000; }}
  .notice.ok {{ background: #e6f6ea; color: #0b5a1f; }}
  @media (prefers-color-scheme: dark) {{
    .notice.error {{ background: #4a1010; color: #ffd6d6; }}
    .notice.ok {{ background: #0f3a1c; color: #cdf5d8; }}
  }}
</style></head><body>
{body}
</body></html>"#
    )
}

fn connections_list(connections: &[Connection]) -> String {
    if connections.is_empty() {
        return "<p><i>No client is connected yet.</i></p>".into();
    }
    let rows: String = connections
        .iter()
        .map(|c| {
            format!(
                r#"<li><b>{}</b> <small>(until {})</small>
                <form method="post" action="/oauth/revoke" class="inline">
                  <input type="hidden" name="client_id" value="{}">
                  <button class="link">Revoke</button></form></li>"#,
                esc(&c.name),
                iso_day(c.expires_ms),
                esc(&c.client_id)
            )
        })
        .collect();
    format!(
        r#"<h2>Connected clients</h2><ul>{rows}</ul>
        <form method="post" action="/oauth/revoke"><button class="danger">Revoke all clients</button></form>"#
    )
}

fn iso_day(ms: f64) -> String {
    let d = worker::js_sys::Date::new(&worker::js_sys::Number::from(ms).into());
    let s: String = d.to_iso_string().into();
    s.chars().take(10).collect()
}

/// The OAuth consent page. The viewer already passed Cloudflare Access.
#[allow(dead_code)]
pub fn consent_page(client_name: &str, p: &AuthorizeParams) -> String {
    let host = worker::Url::parse(&p.redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    let hidden = |k: &str, v: &str| format!(r#"<input type="hidden" name="{k}" value="{}">"#, esc(v));
    let body = format!(
        r#"
        <h1>Allow access to Telegram?</h1>
        <p><b>{name}</b> (redirecting to <code>{host}</code>) wants to use this server:
        read your chats and messages, search, and send to the allowed chats.</p>
        <form method="post" action="/oauth/approve">
          {cid}{ruri}{chal}{state}
          <button name="decision" value="allow">Allow</button>
          <button name="decision" value="deny" class="link">Deny</button>
        </form>"#,
        name = esc(client_name),
        host = esc(&host),
        cid = hidden("client_id", &p.client_id),
        ruri = hidden("redirect_uri", &p.redirect_uri),
        chal = hidden("code_challenge", &p.code_challenge),
        state = p.state.as_deref().map(|s| hidden("state", s)).unwrap_or_default(),
    );
    shell(&body)
}

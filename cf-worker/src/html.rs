//! The login page. Plain HTML forms, no JavaScript, so it works from a phone.

use crate::telegram::Stage;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn login_page(stage: Option<&Stage>, notice: Option<(&str, bool)>) -> String {
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
            <form method="post" action="/logout"><button class="danger">Log out and forget the key</button></form>"#,
            esc(name),
            user_id
        ),
    };

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
  details {{ margin-top: 2rem; }}
  .notice {{ padding: .6rem .8rem; border-radius: 4px; }}
  .notice.error {{ background: #fde8e8; color: #7a0000; }}
  .notice.ok {{ background: #e6f6ea; color: #0b5a1f; }}
  @media (prefers-color-scheme: dark) {{
    .notice.error {{ background: #4a1010; color: #ffd6d6; }}
    .notice.ok {{ background: #0f3a1c; color: #cdf5d8; }}
  }}
</style></head><body>
{notice}
{body}
</body></html>"#
    )
}

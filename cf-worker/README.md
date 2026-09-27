# Cloudflare Worker (Rust): Telegram as a user account, no server

A Cloudflare Worker, written in Rust and compiled to WebAssembly, that talks
MTProto to Telegram as *your account* (not a bot). It logs in from a web page
served by the Worker itself, so no session string or phone code ever passes
through anything but Telegram and Cloudflare.

It serves a small MCP server at `/mcp` with four tools: `list_chats`,
`get_messages`, `search_messages`, and `send_message` (the last restricted to
an allow-list of chats). Everything else is read-only.

## How it works

| Piece | Role |
| --- | --- |
| `src/mtproto.rs` | Drives [`grammers-mtproto`](https://codeberg.org/Lonami/grammers) (sans-IO) over an outbound WebSocket to Telegram's `*.web.telegram.org/apiws` endpoints with the obfuscated intermediate transport. One RPC at a time. Also runs the auth-key Diffie-Hellman exchange. |
| `src/telegram.rs` | Login (`auth.sendCode`, `auth.signIn`, SRP `auth.checkPassword`), `PHONE_MIGRATE` handling, logout, `messages.getDialogs`. |
| `src/account.rs` | A Durable Object named `account`. Holds the authorization in its storage and serializes every Telegram call, so the auth key is never used from two connections at once (Telegram invalidates keys it sees concurrently from different IPs, and Workers egress from many). |
| `src/html.rs` | The login page: plain HTML forms, works from a phone. |
| `src/tools.rs` | The tool implementations: dialogs, history, search, send. Keeps a cache of peer access hashes in Durable Object storage. |
| `src/mcp.rs` | JSON-RPC framing for the streamable-HTTP MCP transport (stateless: one POST per message, JSON responses) and the tool catalogue. |
| `src/lib.rs` | The Worker entry: verifies the Cloudflare Access JWT, forwards to the Durable Object. |
| `src/access.rs` | Fetches the Zero Trust team's signing keys and validates `Cf-Access-Jwt-Assertion` (RS256, `aud`, `iss`, `exp`). |
| `src/session.rs` | Optional import of a Telethon `StringSession` (from the repo's `session_string_generator.py`). |
| `vendor/grammers-mtproto` | Unmodified copy of the crate except `std::time` → `web-time`, because `SystemTime::now()` panics on `wasm32-unknown-unknown`. Wired in through `[patch.crates-io]`. |

## Deploying

Everything is deployed by the GitHub Actions workflow
`.github/workflows/cf-worker-deploy.yml` (manual "Run workflow" button, or
automatically when `cf-worker/` changes on `main`). No local machine needed.

One-time setup:

1. **Repository secrets** (GitHub → Settings → Secrets and variables →
   Actions): `CLOUDFLARE_API_TOKEN` (create at dash.cloudflare.com → My
   Profile → API Tokens → "Edit Cloudflare Workers" template; add
   `Zone:DNS:Edit` on `incende.fyi` so wrangler can create the custom-domain
   record) and `CLOUDFLARE_ACCOUNT_ID`.
2. Run the workflow once. It creates the Worker `telegram-mcp` and binds
   `telegram.incende.fyi` to it.
3. **Worker secrets** (Cloudflare dashboard → Workers & Pages → telegram-mcp
   → Settings → Variables and Secrets): `TELEGRAM_API_ID` and
   `TELEGRAM_API_HASH` from <https://my.telegram.org/apps>.
4. **Access.** The hostname is protected by a Cloudflare Access application
   (`telegram-mcp` in Zero Trust → Access → Applications). Its policies allow
   the owner's email through a one-time PIN, and the `claude-mcp` service
   token for non-interactive MCP clients. The Worker additionally verifies
   the Access JWT against `ACCESS_TEAM_DOMAIN` / `ACCESS_AUD` in
   `wrangler.jsonc`, and `workers.dev` / preview URLs are disabled, so there
   is no path around Access. If the application is recreated, update
   `ACCESS_AUD`.
5. Open `https://telegram.incende.fyi/login` on your phone. Access asks for
   your email and emails you a PIN; then enter your Telegram number, the
   code Telegram sends, and your cloud password if you have one.
6. Open `https://telegram.incende.fyi/spike`. It returns your 20 most recent
   chats as JSON with `total_ms`. That is the connection test.

## Connecting an MCP client

The endpoint is `https://telegram.incende.fyi/mcp`. It sits behind Cloudflare
Access, so a non-interactive client authenticates with the `claude-mcp`
service token (Zero Trust → Access → Service auth). Claude Code:

```bash
claude mcp add --transport http telegram https://telegram.incende.fyi/mcp \
  --header "CF-Access-Client-Id: <client id>" \
  --header "CF-Access-Client-Secret: <client secret>"
```

Codex and other clients that speak streamable HTTP work the same way as long
as they can send those two headers.

### Allowing sends

`send_message` refuses every chat until the Worker variable
`ALLOWED_SEND_CHATS` lists it: a comma-separated list of chat ids as printed
by `list_chats`, e.g. `-1001234567890` is *not* the format; use the bare id
the tool returns (`1234567890`). Set it as a plaintext variable in Workers &
Pages → telegram-mcp → Settings → Variables and Secrets (it survives deploys
thanks to `keep_vars`). Leave it unset for a read-only server.

`POST /logout` (the button on the login page) calls `auth.logOut` and
deletes the stored key.

## Cost per call

Every tool call opens a fresh WebSocket to Telegram (about 0.6–1.2 s to the
home datacenter) and runs one RPC (150–300 ms), so expect 1–2 s per call.
The login's key exchange measured about 100 ms of CPU and completed on the
free plan; ordinary calls use a few milliseconds.

## Status

Login (key exchange, `PHONE_MIGRATE`, code, two-step password) and
`messages.getDialogs` have been exercised end to end from Cloudflare against
a real account. Unit tests cover the session-string parser, error parsing and
storage serialization (`cargo test --target x86_64-unknown-linux-gnu --lib`).

## Security model

What protects the account, and what each layer assumes:

- **Cloudflare Access** is the front door. Only the owner's email (one-time
  PIN) and the `claude-mcp` service token pass. `workers.dev` and preview
  URLs are disabled, so the Access-protected hostname is the only route.
- **The Worker re-verifies** every request's Access JWT (signature against
  the team's published keys, audience, issuer, expiry). A request that
  somehow reached the Worker without Access would still be refused.
- **Browser-originated cross-site requests are refused** (`Origin` /
  `Sec-Fetch-Site` check), and Access's cookie is `HttpOnly`, `SameSite=Lax`
  and bound to the browser, so another site cannot drive the forms or the
  MCP endpoint with the owner's session.
- **Responses are `Cache-Control: no-store`**, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, with a CSP that permits only the page's own
  inline styles and same-origin forms.
- **The auth key** (equivalent to a logged-in device) lives only in the
  Durable Object's storage, encrypted at rest by Cloudflare. It never
  appears in logs, responses, or the repository. `TELEGRAM_API_ID` /
  `TELEGRAM_API_HASH` are Worker secrets.
- **Logs** record the method and path of each request and the byte counts of
  transport frames, nothing else: no identities, phone numbers, query
  strings, message text, or keys.
- **Writes are opt-in.** `send_message` refuses every chat not listed in
  `ALLOWED_SEND_CHATS`; all other tools are read-only. The Worker cannot
  delete, edit, or forward messages, change settings, or manage contacts.
- **Revocation.** The login page's "Log out" calls `auth.logOut` and deletes
  the key. Independently, the session appears in Telegram → Settings →
  Devices as "Cloudflare Worker" and can be terminated there at any time,
  which invalidates the stored key immediately.

Things this does not protect against: whoever holds the `claude-mcp` service
token has the same access as the MCP client (rotate it in Zero Trust if it
leaks); and chat content read through an MCP client goes to that client and
whatever model it talks to.

## Local development

`wrangler dev` runs the Worker locally; outbound WebSockets go out from your
machine. Put `TELEGRAM_API_ID` and `TELEGRAM_API_HASH` in `cf-worker/.dev.vars`
(gitignored) as `NAME=value` lines. Local requests have no Access JWT, so
either run behind `cloudflared access` or temporarily stub `access::verify`.

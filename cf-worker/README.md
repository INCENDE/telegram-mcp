# Cloudflare Worker (Rust): Telegram as a user account, no server

A Cloudflare Worker, written in Rust and compiled to WebAssembly, that talks
MTProto to Telegram as *your account* (not a bot). It logs in from a web page
served by the Worker itself, so no session string or phone code ever passes
through anything but Telegram and Cloudflare.

Current scope: the login flow and one connection test (`/spike`). The MCP
tools come next, once the connection test has run on a real account.

## How it works

| Piece | Role |
| --- | --- |
| `src/mtproto.rs` | Drives [`grammers-mtproto`](https://codeberg.org/Lonami/grammers) (sans-IO) over an outbound WebSocket to Telegram's `*.web.telegram.org/apiws` endpoints with the obfuscated intermediate transport. One RPC at a time. Also runs the auth-key Diffie-Hellman exchange. |
| `src/telegram.rs` | Login (`auth.sendCode`, `auth.signIn`, SRP `auth.checkPassword`), `PHONE_MIGRATE` handling, logout, `messages.getDialogs`. |
| `src/account.rs` | A Durable Object named `account`. Holds the authorization in its storage and serializes every Telegram call, so the auth key is never used from two connections at once (Telegram invalidates keys it sees concurrently from different IPs, and Workers egress from many). |
| `src/html.rs` | The login page: plain HTML forms, works from a phone. |
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

`POST /logout` (the button on the login page) calls `auth.logOut` and
deletes the stored key.

## Plan limits

The auth-key exchange during login and the SRP password check are the two
CPU-heavy steps (2048-bit modular exponentiation in wasm). On the Workers
free plan (10 ms CPU per request) they may exceed the limit; the Workers
Paid plan ($5/month) allows 30 s. Ordinary calls after login are cheap
(AES/SHA over a few kilobytes). If login fails with an "Exceeded CPU" error
in the Worker logs, that is the reason.

## Verified without credentials

- grammers crates compile to `wasm32-unknown-unknown`.
- Bundle: 992 KiB raw, 387 KiB gzipped (limit 3 MiB on the free plan).
- `wrangler deploy --dry-run` passes with the Durable Object binding.
- Session-string parser and DC-migration error parsing are unit-tested
  (`cargo test --target x86_64-unknown-linux-gnu --lib`).

## Not yet verified

The live round trip to Telegram: whether Telegram accepts the WebSocket +
obfuscated-intermediate handshake from a Worker (expected: yes, browsers do
the same), the CPU cost of login against the plan limit, and per-call
latency. The development sandbox this was written in cannot reach
`*.web.telegram.org`, so step 5 above is the test.

## Local development

`wrangler dev` runs the Worker locally; outbound WebSockets go out from your
machine. Put `TELEGRAM_API_ID` and `TELEGRAM_API_HASH` in `cf-worker/.dev.vars`
(gitignored) as `NAME=value` lines. Local requests have no Access JWT, so
either run behind `cloudflared access` or temporarily stub `access::verify`.

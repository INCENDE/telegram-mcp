# Cloudflare Worker (Rust) — feasibility spike

A minimal MTProto client that runs on Cloudflare Workers, written in Rust and
compiled to WebAssembly. It exists to answer one question: can a Worker talk
to Telegram as a *user account* (not a bot) without a long-running process?

This is **not** the MCP server yet. It exposes a single diagnostic endpoint.

## How it works

- [`grammers-mtproto`](https://codeberg.org/Lonami/grammers) does the MTProto
  encoding/encryption. It is sans-IO, so it never opens a socket itself.
- `src/mtproto.rs` drives it over an outbound WebSocket to Telegram's
  `*.web.telegram.org/apiws` endpoints (the same path Telegram Web uses),
  with the obfuscated intermediate transport Telegram requires over WS.
- `src/session.rs` reads a Telethon `StringSession` (the format produced by
  the repo's `session_string_generator.py`), so login happens once, on your
  machine, and the Worker only ever holds the resulting auth key.
- `vendor/grammers-mtproto` is an unmodified copy of the crate except that
  `std::time` is replaced by `web-time`, because `SystemTime::now()` panics on
  `wasm32-unknown-unknown`. Wired in through `[patch.crates-io]`.

## Verified so far (no Telegram credentials needed)

| Check | Result |
| --- | --- |
| grammers crates compile to `wasm32-unknown-unknown` | yes (pin `glass_pumpkin = 2.0.0-rc0`, done in `Cargo.lock`) |
| Bundle size | 752 KiB raw, **293 KiB gzipped** (free-plan limit is 3 MiB) |
| `wrangler deploy --dry-run` | passes |
| Session-string parser | unit-tested (`cargo test --target x86_64-unknown-linux-gnu`) |

## Not yet verified

The actual round trip to Telegram. The development sandbox this was built in
cannot reach `*.web.telegram.org`, so the connection has to be exercised from
Cloudflare itself. Open questions it will settle:

1. Whether Telegram accepts the WebSocket + obfuscated-intermediate handshake
   from a Worker (expected: yes, it is what browsers do).
2. Per-request CPU time on the free plan (10 ms limit). With a pre-generated
   auth key there is no key exchange, only AES/SHA work, so it should fit.
3. Wall-clock latency per call (connect + one RPC).

## Running the spike

Prerequisites: Rust stable, `rustup target add wasm32-unknown-unknown`,
`cargo install worker-build`, and `wrangler` logged in to the account.

```bash
cd cf-worker
wrangler deploy                      # publishes telegram-mcp.<subdomain>.workers.dev

# Secrets. Generate the session string with the repo's generator:
#   uv run session_string_generator.py
wrangler secret put TELEGRAM_API_ID
wrangler secret put TELEGRAM_API_HASH
wrangler secret put TELEGRAM_SESSION_STRING
wrangler secret put SPIKE_TOKEN      # any long random string

curl -H "Authorization: Bearer <SPIKE_TOKEN>" \
  https://telegram-mcp.<subdomain>.workers.dev/spike
```

Expected output: JSON with your first 20 dialogs (`id`, `kind`, `name`,
`unread`) and `connect_ms` / `rpc_ms` / `total_ms` timings. An
`AUTH_KEY_UNREGISTERED` error means the session string is not logged in;
`connection error` means the WebSocket path failed and the response body says
where.

Optional: `TELEGRAM_WS_HOST` (a plain var) overrides the datacenter hostname.

## Local development

`wrangler dev` runs the Worker in a local `workerd`; outbound WebSockets go
out from your machine, so this works anywhere Telegram is reachable. Put the
secrets in `cf-worker/.dev.vars` (gitignored) as `NAME=value` lines.

## Removing it

`wrangler delete` removes the Worker and its secrets.

# Plan: rewrite telegram-mcp in Rust, fix the two weaknesses, remove Groq

## 1. Goal

Replace the Python implementation (about 13,000 lines, 131 MCP tools on Telethon)
with a Rust implementation of the same server, on branch `claude/pensive-gauss-u2jltj`,
delivered as a draft PR. Along the way:

- Remove the Groq transcription engine and every trace of it (code, env vars, docs, docker-compose).
- Fix weakness 1: `export_unread_messages` writes to a caller-supplied path with no
  allowed-roots check and is annotated read-only.
- Fix weakness 2: drop the redundant, abandoned `dotenv` PyPI dependency (moot once Python is gone; the Rust crate uses `dotenvy` for `.env` loading only).

## 2. Stack (decided, verified to compile together)

| Concern | Crate | Notes |
|---|---|---|
| MTProto client | grammers-client 0.10 (+ grammers-session, grammers-tl-types, grammers-mtsender) | Same author as Telethon. `fs`, `markdown`, `html`, `proxy` features. |
| MCP server | rmcp 3.4 (official Rust SDK) | stdio + streamable HTTP transports. |
| HTTP | axum 0.8 | Hosts rmcp's streamable HTTP service. |
| SQLite | rusqlite (bundled) | Transcript cache, session storage, reading Telethon `.session` files. |
| Images | image 0.25 | Contact sheets, without Pillow. |
| Locks | fs4 | flock-based session locks, same file names as the Python version. |
| Misc | tokio, serde, serde_json, schemars 1, chrono, base64, dotenvy, qrcode, mime_guess, sha1/sha2 | |

Pin: `glass_pumpkin` must stay at `2.0.0-rc0` (rc1 breaks grammers-crypto).
grammers-session's own SQLite storage is disabled: it bundles a second libsql copy that
collides with rusqlite at link time. A rusqlite-backed `Session` implementation replaces it.

## 3. Architecture

```
Cargo.toml                    crate telegram-mcp, lib telegram_mcp, three binaries
src/main.rs                   telegram-mcp            (the server)
src/bin/generate_session.rs   telegram-mcp-generate-session (QR or phone login -> string session)
src/bin/migrate_session.rs    telegram-mcp-migrate-session  (string session -> file session)

src/config.rs        env parsing, fail-loud validation (exposed tools, extension allowlists,
                     chat allowlist, proxy, timeouts, transcription mode)          DONE
src/sanitize.rs      control/zero-width stripping, truncation, name sanitising    DONE
src/errors.rs        error codes, flood-wait and schema-drift formatting           DONE
src/session.rs       Telethon string-session codec, Telethon .session import,
                     rusqlite-backed grammers Session storage                      DONE
src/singleton.rs     per-session flock, shared/exclusive modes                     DONE
src/accounts.rs      account discovery (labels, pool, default), client build,
                     connect + authorisation check, cache warm, update stream      DONE
src/aliases.rs       saved-contact store (XDG path, atomic 0600 writes, lock),
                     fuzzy matching with a difflib-ratio port, ask-the-user payloads
src/entity.rs        ChatRef (int | username | alias), marked-id conversion,
                     resolve_peer with cache warm and marked-variant retries,
                     chat allowlist checks, format_entity
src/format.rs        message -> JSON/line rendering, sender info, engagement,
                     media labels, rich-message text flattening
src/paths.rs         MCP roots (client roots/list with timeout, server CLI roots,
                     opt-in fallback), readable/writable path resolution,
                     extension and size limits
src/registry.rs      tool registry: name, annotations, JSON schema (schemars),
                     handler; per-call pipeline = id validation + alias
                     substitution + allowlist check + multi-account fan-out +
                     timeout + audience=user annotation on every content block
src/server.rs        rmcp ServerHandler (list_tools/call_tool over the registry),
                     exposure-mode pruning, stdio and HTTP serving, startup
src/transcription.rs native Telegram Premium transcription only, SQLite cache,
                     per-listing budget, voice rendering helpers
src/photo_source.rs  avatar/message photo references, in-memory download
src/contact_sheet.rs labelled JPEG grid with an embedded bitmap font
src/events.rs        incoming-message tracker, settle/debounce, JSONL feed file
src/tools/*.rs       accounts, chats, contacts, events, folders, groups, media,
                     messages, profile  (131 tools, same names, same parameters)
tests/               integration tests for the pure logic
```

Tool handlers are plain `async fn(Arc<Server>, ToolCtx, Params) -> ToolOutput` registered
with metadata. The registry, not the handler, does what Python's `@validate_id`,
`@with_account` and the annotation hook did, so every tool gets identical behaviour.

## 4. Behaviour kept from the Python version

- All 131 tool names, parameters, defaults, annotations and result shapes (JSON boundary,
  sanitised strings, error codes, ask-the-user alias payloads).
- Environment variables and their semantics, including `TELEGRAM_EXPOSED_TOOLS`,
  `TELEGRAM_FILE_EXTENSIONS`, `TELEGRAM_ALLOWED_CHAT_IDS`, `TELEGRAM_ALLOWED_ROOTS`,
  roots fallback and timeout, session pool, session lock, device identity, aliases file,
  event feed, transcription mode and budget.
- Session compatibility: existing `TELEGRAM_SESSION_STRING` values load unchanged.
  `TELEGRAM_SESSION_NAME` file sessions are imported on first run from the Telethon
  `.session` file (auth key, DC, cached entities) into `<name>.grammers.session`; the
  Telethon file is never modified.
- Lock file names and digests, so a Python and a Rust instance exclude each other.
- Multi-account fan-out for read-only tools, bot-account handling, flood-wait wording.

## 5. Deliberate changes

1. Groq removed. `TELEGRAM_TRANSCRIBE_ENGINE` accepts only `telegram`; any other value
   aborts startup with a clear message. `GROQ_API_KEY` and `TELEGRAM_TRANSCRIBE_GROQ_MAX_MB`
   are gone. `transcribe_voice` loses its `engine` parameter. The docker-compose comments
   and README sections about Groq are rewritten.
2. `export_unread_messages` resolves `output_path` through the shared writable-path guard
   (allowed roots, no traversal, no wildcards) and is annotated as a write tool
   (`readOnlyHint` removed), which also means the read-only exposure mode hides it.
3. Legacy SSE transport dropped: rmcp 3 ships stdio and streamable HTTP only.
   `MCP_TRANSPORT=sse` aborts with a message pointing at `http`.
4. Proxies: SOCKS5 only. grammers has no SOCKS4, HTTP-CONNECT or MTProxy support.
   Those values abort startup with a message instead of silently bypassing the proxy.
5. The PyPI-collision install guard is gone; it protected against a Python packaging
   problem that does not exist for a Rust binary.
6. Error codes are stable across restarts (FNV hash of the function name instead of
   Python's per-process randomised `hash`).

## 6. Work breakdown and status

| # | Step | Status |
|---|---|---|
| 1 | Core: manifest, config, sanitize, errors, session codec + storage, locks, accounts | done, 24 unit tests green |
| 2 | Shared runtime: aliases, entity, format, paths, registry, server | next |
| 3 | transcription (native only), photo_source, contact_sheet, events core | after 2 |
| 4 | Port the 9 tool modules (131 tools) with parallel worker agents, one module each, in isolated worktrees against the frozen core API; I merge and fix | after 3 |
| 5 | Binaries (generate/migrate session), Dockerfile (multi-stage Rust, non-root), CI (fmt, clippy, test, docker), README + .env.example + claude_desktop_config.json, remove all Python sources, tests, lockfiles and pre-commit config | after 4 |
| 6 | Full `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`; commit; push; draft PR | last |

## 7. Testing

- Unit tests per module for every pure function (config parsing, sanitiser, session codec,
  session storage round trip, locks, alias matching tables, path guard, allowlist,
  exposure pruning, registry pipeline with a fake handler, schedule-date parsing,
  contact-sheet layout, transcript cache, event settle logic).
- No live Telegram access exists in this environment, so network paths are verified by
  compiling against grammers' typed API and by review, not by a live login. This is the
  main residual risk and is stated in the PR.

## 8. Risks and mitigations

- grammers 0.10 is younger than Telethon; some raw TL calls (forum topics, folders,
  invite links, profile edits) use `client.invoke` with generated types directly. The
  TL layer is fixed at build time, so schema drift surfaces as a build update, not a
  runtime desync.
- Compile time: the dependency set builds in a few minutes cold; CI caches it.
- Scale: the port lands as one PR. It is reviewable module by module because the Rust
  file layout mirrors the Python one.

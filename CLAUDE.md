# Claude briefing — `simple-analytics`

You are helping maintain a Rust analytics micro-service. Read this first; it
contains the project-specific conventions and landmines that aren't obvious
from the code.

User-facing docs live in [README.md](./README.md), [INSTALL.md](./INSTALL.md),
[API.md](./API.md). This file is for contributors (human or Claude).

---

## What it is

Single-binary HTTP service on **Axum 0.8 + SQLx 0.8.6 + SQLite WAL**. Rust
1.94, edition 2024. Deployed behind a reverse proxy in front of a high-value
target — **security mistakes are catastrophic**. When in doubt, default to
the conservative/locked-down behavior.

Tree:

```
src/
  lib.rs              build_app, router assembly, cors, /healthz & /readyz
  main.rs             bin entrypoint, background-worker supervision, graceful shutdown
  config.rs           figment-loaded Config with tight validation
  state.rs            AppState: pool + limiters + salts + delivery Notify
  db.rs               SQLite connect + PRAGMAs + in_memory_for_tests
  auth.rs             WriteAuth/ReadAuth/AdminAuth/BeaconAuth extractors, key redaction
  rate_limit.rs       token-bucket limiter cache (moka)
  visitor.rs          daily salt rotation + visitor_hash
  user_token.rs       blake3-keyed sign/verify for `user` payloads
  net.rs              SSRF defenses + DNS pinning for outbound HTTP
  ingest/mod.rs       /collect + beacon handler, insert_event, size/shape guards
  ingest/parse.rs     UA/device parsing, UTM extraction, source classification
  ingest/validator.rs optional external URL-validator client (cached)
  query/mod.rs        /events, shared EventFilters + push_filters builder
  query/aggregates.rs /stats, /stats/urls, /stats/pages, /stats/user_pages + refresh worker
  query/export.rs     /export CSV/NDJSON streaming + formula-injection scrub
  webhooks/mod.rs     /webhooks CRUD (admin)
  webhooks/delivery.rs durable delivery queue with exp. backoff, HMAC signing, DNS pinning
  wal_checkpoint.rs   periodic PRAGMA wal_checkpoint(TRUNCATE) worker
  retention.rs        periodic row deletion per [retention] config
  beacon.rs           /s.js renderer (script snippet)
  geoip.rs            optional MaxMind lookup
  error.rs            AppError → uniform {"error":{...}} JSON
  model.rs            IncomingEvent + EventType enum

tests/it/             integration tests (in-memory SQLite, one `build()` helper)
migrations/           forward-only sqlx migrations
examples/             load_test.rs, sign_user.rs
scripts/              loadtest-run.sh
```

---

## Runtime shape

`main.rs` spawns four `tokio::spawn`-supervised workers: `aggregates`,
`webhook_delivery`, `retention`, `wal_checkpoint`. Each is wrapped in
`supervise()` so a panic restarts it with exponential backoff. The HTTP
`axum::serve` runs on its own task with `with_graceful_shutdown`. On
SIGTERM/Ctrl+C a watch channel flips; the serve task drains for up to 30s,
then workers get another 10s each.

**Do not** put the serve future inside `tokio::time::timeout` — that caps
the entire server lifetime, not just shutdown. This was a real bug; preserve
the current shape.

---

## HTTP + DB conventions

- **Handlers return `AppResult<impl IntoResponse>`.** Use `AppError` variants
  (`BadRequest`, `NotFound`, `RateLimited`, `Internal`, …) — they serialize
  to the uniform `{"error":{"code":"...","message":"..."}}` body.
- **All SQL parameters go through `push_bind` / `bind`.** No string
  interpolation, ever. `QueryBuilder` is the canonical way to build
  conditional filters; see `query::push_filters` and `query::aggregates::*_handler`.
- **Use `sqlx::FromRow`** on response structs when the column set is fixed.
  For `/events` and `/export` the column list lives in the shared
  `EVENTS_COLUMNS` constant — add new columns there once.
- **Never put raw-key strings in a log, `Debug` derive, or cache key.**
  `auth.rs` holds a fixed-width fingerprint; rate-limit caches key off that.
- Routes are registered per-module in `routes()` functions and merged in
  `lib.rs::build_app_with_pool`. A new endpoint belongs in an existing module
  if it fits; otherwise add a module and `.merge(new_module::routes())`.

---

## Testing

All tests run against an **in-memory SQLite pool**:

```rust
use super::common::*;
let (router, state) = build().await;
```

`tests/it/common.rs` exposes fixtures (`WRITE_KEY`, `READ_KEY`, `ADMIN_KEY`,
`SITE_TOKEN`, `USER_SIGNING_SECRET`), builders (`collect_body`, `collect_req`,
`beacon_req`, `get_req`, `admin_req`), `sign_user()`, and `build_with()` for
config tweaks. Ingest goes through `/collect` so events take the real
validation + visitor-hash path — prefer that over `sqlx::query("INSERT INTO events ...")`.

Aggregate endpoints (`/stats`, `/stats/urls`) test by calling
`simple_analytics::query::aggregates::refresh(&state.pool).await.unwrap()`
directly — don't wait for the worker tick.

Run:

```sh
cargo test                 # full suite
cargo test --test it <name>  # one file / test
cargo clippy --all-targets
cargo fmt
```

No external services. No flaky tests — if yours is, it's wrong.

---

## Landmines

### `serde_urlencoded` + numeric types through `#[serde(flatten)]`

Doesn't work. Query-string deserialization through a flattened struct
rejects any numeric field with "invalid type: string, expected i64". That's
why `ExportQuery` duplicates fields from `EventFilters` instead of flattening
it. If you need to share filter shape across two endpoints, expose a
`to_filters()` method rather than `#[serde(flatten)]`.

### SQLite WAL growth

`PRAGMA wal_autocheckpoint` is PASSIVE — it can't reset the WAL while any
reader holds a snapshot. Under sustained ingest with concurrent reads the
WAL grows without bound. The `wal_checkpoint` worker runs
`PRAGMA wal_checkpoint(TRUNCATE)` on an interval to cap it. Don't disable
this worker in production (`database.wal_checkpoint_interval_secs = 0`
logs a warning and lets the WAL grow forever — it's a footgun, not a
feature).

### Shutdown timeout must gate on SIGTERM, not on serve

`tokio::time::timeout(30s, axum::serve(...))` caps total server lifetime.
The correct shape — spawn serve, await SIGTERM, **then** start a 30s timer
on the join handle — is in `main.rs`. If you're refactoring startup, don't
flatten this back.

### Privacy default: `visitor_hash` is omitted

`privacy.expose_visitor_hash = false` (the default) means `/events`,
`/export` (ndjson) and `/stats/user_pages` must not return the hash. The
test config flips it to `true` because the tests assert on it. Any new
read endpoint that returns event rows must honor this flag.

### CSV export scrubs formula injection

`query::export::csv_*` prefixes cells starting with `=`, `+`, `@`, `-`, tab
or CR with an apostrophe, and replaces CR/LF with the escape `"""…"""` so
Excel/Calc can't interpret them as formulas. New CSV fields go through the
same path — don't hand-roll CSV writing.

### SSRF defenses are opt-out, not opt-in

`net::validate_webhook_url_async` is called before accepting a webhook URL
or validator URL. It rejects loopback / RFC-1918 / link-local / CGNAT /
cloud-metadata / embedded userinfo / non-http(s) schemes. The delivery
worker re-validates and pins the resolved IP. Preserve both layers.

### Event column list

`query::EVENTS_COLUMNS` is the source of truth for `SELECT *`-shaped reads.
When you add a column to `events`:

1. Write a new migration under `migrations/`.
2. Append the column to `EVENTS_COLUMNS`.
3. Add the field to `EventRow`.
4. Update webhook-delivery payload loader if it reads the same columns.

---

## Adding a new endpoint

1. **Decide which module it belongs to** (`query`, `ingest`, `webhooks`,
   or a new module `mod foo;` in `lib.rs` + `.merge(foo::routes())`).
2. **Pick the auth tier.** Reads → `ReadAuth`. Writes → `WriteAuth`.
   Admin ops → `AdminAuth`. Browser → `BeaconAuth`.
3. **Define request params** with `#[derive(Deserialize, Default)]`.
   Clamp integer params with `.clamp(min, max)` — never trust caller values.
   Required params should be `Option<T>` + explicit check returning
   `AppError::BadRequest`; that gives a clean 400 message instead of serde's
   422.
4. **Build queries via `QueryBuilder` + `push_bind`**. Follow
   `query::aggregates::page_stats_handler` for the shape.
5. **Register the route** in the module's `routes()` function.
6. **Add integration tests** in `tests/it/<file>.rs`:
   `requires_<key>`, behavior, edge cases, filter interactions. Mirror the
   existing `url_stats_*` tests for style.
7. **Document it** in `API.md` under the appropriate section.

---

## Adding a new filter to `/events` (and `/export`)

1. Add the field to `EventFilters` in `query/mod.rs`.
2. Add the `push_bind` branch in `push_filters()`.
3. If the column doesn't have a `(col, ts)` index, add one in a new
   migration — an unindexed filter will table-scan under load.
4. Duplicate the field on `ExportQuery` in `query/export.rs` and copy it in
   `to_filters()`.
5. Test both endpoints (`tests/it/query.rs`, `tests/it/export.rs`).

---

## Adding a config key

1. Add the field to the right struct in `src/config.rs` with a
   `default_` function and `#[serde(default = "default_xxx")]`.
2. Update the struct's `Default` impl (integration tests build configs by
   hand; missing fields break them).
3. If it's a path / URL / bounded int, add validation in `Config::validate`.
4. Document it in `config.example.toml` with a comment explaining *why*,
   not just *what*.

---

## Style

- **Comments answer "why", not "what".** If the code is clear, no comment.
  If an invariant or a non-obvious constraint motivates the shape, write
  that down. Existing comments are a good template.
- **Early returns, fail fast.** No nested `if let Some(_) = ... { ... }`
  ladders; flatten with `let Some(x) = ... else { return Err(...); };`.
- **No dead code.** Remove it rather than commenting it out.
- **Prefer built-in crates already in `Cargo.toml`** over adding new deps.
  `blake3`, `reqwest`, `time`, `url`, `serde_json`, `moka`, `tokio` are all
  already here; check before pulling in another.
- Comments are lowercase, short, in sentence form. No "TODO:" — file a
  real issue instead.
- Run `cargo fmt` and `cargo clippy --all-targets` before committing; both
  should be clean.

---

## Security posture (non-negotiable)

- **Never log raw keys, secrets, or `user` payloads.** `tracing` fields must
  be fingerprints / ids / counts, never the underlying value.
- **Constant-time compare** for anything auth-related. Use
  `crate::crypto::constant_time_eq` or the helpers in `auth.rs`.
- **Uniform error responses for auth.** Don't invent a new 403 or a more
  helpful message for "bad signature" vs "missing signature" — both go
  through `AppError::Unauthorized`.
- **SSRF-check every outbound URL** that came from an untrusted source
  (webhook creation, validator config, anything else new).
- **Parameterize every query.** Zero exceptions.
- **Treat the DB file as secret material.** It stores webhook secrets and
  visitor hashes. Don't add anything that would make a leaked backup worse.

If a change touches auth / crypto / SSRF / SQL construction / the event
shape, flag it in the PR description and ask for a review. Those areas are
where bugs turn into incidents.

---

## Quick references

- Regenerate a user signature from the CLI:
  `cargo run --example sign_user -- "$USER_SECRET" '{"id":"42"}'`
- Run the load-test harness locally:
  `scripts/loadtest-run.sh`
- Inspect the SQLite DB:
  `sqlite3 data/analytics.db '.schema events'`
- Tail structured logs:
  `RUST_LOG=simple_analytics=debug,sqlx=warn LOG_FORMAT=json cargo run`

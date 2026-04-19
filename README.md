# simple-analytics

Self-hosted, cookieless analytics in a single container. SQLite on disk, HTTP
API for ingest, query, aggregates, CSV/NDJSON export and outbound webhooks.

Rust + Axum + SQLx. One binary, one DB file. Put it behind a reverse proxy.

## Highlights

- Server and browser ingest (write key, or public site token + origin allowlist).
- Cookieless: daily-rotated `blake3_keyed(site_salt, ip | ua)` visitor hash.
- Signed `user` attribution (HMAC) so browser events can't be forged.
- Pre-computed aggregates: `/stats`, `/stats/urls`, `/stats/pages`,
  `/stats/user_pages`, `/stats/sources`, `/stats/timeseries`, `/stats/funnels`,
  `/stats/new_returning`.
- Streaming `/export` (CSV / NDJSON) with the same filters as `/events`.
- Durable webhook queue with HMAC signing, SSRF defenses, exponential backoff.
- Ad-blocker resistant defaults (`/e`, `/s.js`, `x-id`, `window.sa`).
- Prometheus `/metrics`, OpenAPI at `/openapi.json`, SIGHUP hot-reload.

## Quick start

```sh
cp .env.example .env   # or write one: see INSTALL.md
docker compose up -d
```

```sh
curl -X POST http://localhost:8080/collect \
  -H "content-type: application/json" \
  -H "x-write-key: $WRITE_KEY" \
  -d '{"type":"pageview","url":"https://example.com/","user_agent":"Mozilla/5.0","ip":"203.0.113.10"}'
```

## Docs

- [INSTALL.md](./INSTALL.md): install, configure, update.
- [API.md](./API.md): full HTTP reference.
- [CLAUDE.md](./CLAUDE.md): contributor notes.
- [config.example.toml](./config.example.toml): every key, with defaults.

## Development

```sh
cargo test
cargo clippy --all-targets
cargo fmt
```

Tests use an in-memory SQLite pool. No external services.

# HTTP API reference

Every endpoint, every field, every error. For install/deploy see
[INSTALL.md](./INSTALL.md). For the why, see [README.md](./README.md).

---

## Conventions

- Content type is always `application/json` unless otherwise noted.
- Timestamps are unix milliseconds (i64).
- Event bodies are capped at `server.max_body_bytes` (default 64 KB).
- Keys are sent in headers; never in query strings or bodies.

### Error shape

Every error response is:

```json
{ "error": { "code": "invalid_segment", "message": "segment 'x' is not in the allowed list" } }
```

Common codes: `bad_request`, `unauthorized`, `forbidden`, `not_found`,
`payload_too_large`, `rate_limited`, `internal_error`.

### Auth tiers

| header | required by | generate with |
|---|---|---|
| `x-write-key` | `POST /collect` | `openssl rand -hex 32` (≥32 chars) |
| `x-read-key`  | `GET /events`, `/stats*`, `/export` | `openssl rand -hex 32` |
| `x-admin-key` | `/webhooks*` | `openssl rand -hex 32` |
| `x-id` (configurable) | browser beacon | `openssl rand -hex 16` (site token, public) |

All key comparisons are constant-time against a fixed-width fingerprint.
`Debug` output redacts the keys.

### Rate limits

Token buckets. All caps and bursts are configurable under `[ingest]`.

| bucket | default | what it protects |
|---|---|---|
| per-IP pre-auth | 60k/min, burst 5k | auth-oracle probing |
| per-write-key | 6k/min, burst 500 | flood from a leaked write key |
| per-read-key | 120/min, burst 60 | bulk-scraping from a leaked read key |
| per-IP (browser) | 120/min, burst 30 | single abusive browser |
| per-site-token (browser) | 60k/min, burst 5k | IP-rotating abuse with a leaked site token |

When any bucket is empty the response is `429` with the standard error body.
The pre-auth per-IP bucket applies **before** key validation — a wrong key
and a valid-key-over-quota both return `429`, so the endpoint doesn't leak
which keys exist.

---

## Ingestion

### `POST /collect` — server-side

Authenticated with `x-write-key`. Caller supplies `user_agent` and `ip`
because they know the originating request.

Request body:

```json
{
  "type":        "pageview",
  "name":        null,
  "url":         "https://example.com/pricing?utm_source=hn",
  "title":       "Pricing",
  "referer":     "https://news.ycombinator.com/",
  "segments":    ["paid", "club100"],
  "user_agent":  "Mozilla/5.0 (...) Chrome/123.0",
  "ip":          "203.0.113.10",

  "user":        "{\"id\":\"42\",\"plan\":\"pro\"}",
  "user_sig":    "aabbcc... (hex blake3 MAC)",

  "search":      { "query": "foo", "result_count": 12, "results": ["a","b"], "clicked_result": "a" },
  "extra":       { "any": "json object" }
}
```

| field | type | notes |
|---|---|---|
| `type` | enum | `pageview` \| `search` \| `custom` |
| `name` | string? | human-readable event name (required for `custom`) |
| `url` | string | full URL incl. query — UTM params are extracted into separate columns |
| `title` | string? | `≤ 1 KB` |
| `referer` | string? | `≤ 2 KB` |
| `segments` | string[] | `≤ 32` entries, each `≤ 128 B`; validated against `ingest.allowed_segments` if set |
| `user_agent` | string | `≤ 2 KB`, required |
| `ip` | string | `v4` or `v6`; used for the daily-rotating visitor hash, not stored |
| `user` | string? | signed JSON payload (see [User attribution](#user-attribution)); `≤ 4 KB` |
| `user_sig` | hex string? | required iff `user` is set; 64 hex chars |
| `search` | object? | required when `type=search` |
| `extra` | object? | `≤ 8 KB` as JSON |

Response: `202 Accepted`

```json
{ "id": 12345 }
```

Errors: `400` (validation / too big / invalid UTF-8), `401` (auth),
`413` (body > `server.max_body_bytes`), `429` (rate limit),
`500` (DB or validator failure when `fail_open=false`).

### `POST /e` — browser beacon

The path is configurable — `endpoints.browser_collect_path`, default `/e`.
Same body as `/collect` but **without** `user_agent` or `ip`; those come from
the request.

Auth is the configurable header (default `x-id`) carrying
`auth.site_token`, plus an `Origin` header that must match
`auth.allowed_origins`. Any origin mismatch or missing header returns a
uniform `401` so you can't use the endpoint as an oracle.

### `GET /s.js` — browser snippet

The path is configurable — `endpoints.browser_script_path`, default `/s.js`.
Returns a ~3 KB JS snippet with the config values (paths, header name,
namespace) baked in.

```html
<script
  src="https://analytics.example.com/s.js"
  data-endpoint="https://analytics.example.com/e"
  data-site-token="YOUR_PUBLIC_SITE_TOKEN"
  data-segments='["paid"]'
  data-user='{"id":"42"}'
  data-user-sig="aabbcc..."
  defer
></script>
```

After load, `window.sa` (namespace configurable) exposes:

```js
sa.pageview(opts?);
sa.search({ query, result_count, results, clicked_result });
sa.custom(name, extra, opts?);
sa.identify({ user, user_sig });   // attach signed user to later events
sa.setSegments(["paid"]);          // per-page segment override
```

`opts` is `{ url?, title?, segments? }`. The snippet auto-sends an initial
`pageview` and hooks `history.pushState` / `popstate` for SPA navigation.

---

## Query

All query endpoints require `x-read-key`.

### `GET /events`

Raw event query with filters and pagination.

| param | type | description |
|---|---|---|
| `from`, `to` | unix-ms | inclusive range |
| `event_type` | string | `pageview`, `search`, `custom` |
| `source` | string | `twitter`, `google`, `direct`, `hackernews`, … |
| `device_type` | string | `mobile` \| `tablet` \| `desktop` \| `bot` |
| `segment` | string | any event whose segments array contains this value |
| `url` | string | exact match |
| `user_id` | string | decoded id from a signed `user` payload |
| `country` | string | 2-letter ISO code (case-insensitive) |
| `limit` | int | default 100, max 1000 |
| `offset` | int | paginate forward; response includes `next_offset` |

Response:

```json
{
  "events": [
    {
      "id": 42, "ts": 1745100000000, "event_type": "pageview",
      "url": "https://example.com/", "title": "Home",
      "user_agent": "...", "device_type": "desktop", "device_os": "macOS",
      "device_browser": "Safari", "referer": "https://news.ycombinator.com/",
      "source": "hackernews",
      "utm_source": null, "utm_medium": null, "utm_campaign": null,
      "utm_term": null, "utm_content": null,
      "segments": ["paid"], "extra": null,
      "user_id": "42", "user": {"id":"42","plan":"pro"},
      "country": "FR"
    }
  ],
  "next_offset": 100
}
```

`next_offset` is `null` on the last page.

`visitor_hash` is only included when `privacy.expose_visitor_hash = true`
(default `false`).

### `GET /stats`

Pre-computed daily rollups. Reads from `agg_daily`.

| param | type | description |
|---|---|---|
| `from_day`, `to_day` | `YYYY-MM-DD` (UTC) | inclusive range |
| `event_type`, `source`, `segment`, `device_type`, `country` | string | exact match |

Response: array of `{ day, event_type, source, segment, device_type, country, count, visitors }`.

Rows with `segment = null` are the "all segments" rollup; rows with
`country = null` are the "all countries" rollup (always present if GeoIP is
disabled).

### `GET /stats/urls`

Per-day, per-URL rollup. Reads from `agg_daily_url`.

| param | type | description |
|---|---|---|
| `from_day`, `to_day` | `YYYY-MM-DD` | inclusive |
| `event_type` | string | e.g. `pageview` |
| `url` | string | exact match |
| `limit` | int | default 1000, max 10000; sorted by `count DESC` |

Response: array of `{ day, url, event_type, count, visitors }`.

### `GET /stats/pages`

Hits per page, **aggregated across a time range** (not per-day). Reads the
raw `events` table so `visitors` is an accurate `COUNT(DISTINCT visitor_hash)`
over the full range (you can't sum distinct-counts across days).

| param | type | description |
|---|---|---|
| `from`, `to` | unix-ms | inclusive range (optional) |
| `event_type` | string | default `pageview` |
| `limit` | int | default 1000, max 10000; sorted by `count DESC` then `url ASC` |

Response:

```json
[
  { "url": "https://example.com/",      "count": 1234, "visitors": 890, "last_ts": 1745100000000 },
  { "url": "https://example.com/pricing","count":  612, "visitors": 501, "last_ts": 1745099000000 }
]
```

Use `/stats/urls` when you want the per-day breakdown. Use `/stats/pages`
when you want totals over a window.

### `GET /stats/user_pages`

Pages viewed by a single attributed user. Requires a `user_id` — attributed
users come from signed `user` payloads (see [User attribution](#user-attribution)),
so anonymous visitors don't have one. Reads the raw `events` table filtered
by `user_id`, which uses the partial index `idx_events_user_ts`.

| param | type | description |
|---|---|---|
| `user_id` | string | **required** |
| `from`, `to` | unix-ms | inclusive range (optional) |
| `event_type` | string | default `pageview` |
| `limit` | int | default 1000, max 10000; sorted by `last_ts DESC` |

Response:

```json
[
  { "url": "https://example.com/pricing", "count": 3, "first_ts": 1744900000000, "last_ts": 1745099000000 },
  { "url": "https://example.com/",        "count": 1, "first_ts": 1745050000000, "last_ts": 1745050000000 }
]
```

Missing `user_id` returns `400 bad_request`.

### `GET /stats/sources`

Top referrers / `utm_source`s over a time range.

| param | type | description |
|---|---|---|
| `from`, `to` | unix-ms | optional |
| `event_type` | string | optional |
| `limit` | int | default 1000, max 10000; sorted `count DESC` |

Response: `[{ source, count, visitors }]`. `source` can be `null` for
untracked traffic.

### `GET /stats/timeseries`

Event counts bucketed by hour or day. Buckets with zero events are omitted.

| param | type | description |
|---|---|---|
| `from`, `to` | unix-ms | optional |
| `event_type`, `url`, `source`, `country`, `user_id` | string | optional exact-match filters |
| `granularity` | `hour` \| `day` | default `hour` |
| `limit` | int | default 10000, max 10000 |

Response: `[{ bucket, count, visitors }]` where `bucket` is ISO-8601 UTC
at hour or day precision.

### `GET /stats/searches`

Top search queries over a time range. Reads `event_type='search'` rows.

| param | type | description |
|---|---|---|
| `from`, `to` | unix-ms | optional |
| `zero_only` | bool | when true, return only queries whose avg result count is 0 |
| `limit` | int | default 100, max 10000; sorted `count DESC` |

Response: `[{ query, count, visitors, avg_result_count, zero_result_count }]`.

### `GET /stats/user_timeline`

Chronological event list for a user. Support-style "what did this user do".

| param | type | description |
|---|---|---|
| `user_id` | string | **required** |
| `from`, `to` | unix-ms | optional |
| `limit` | int | default 500, max 10000 |

Response: `[{ ts, event_type, event_name, url, page_title, source, device_type, session_id }]`.

### `GET /stats/funnels`

Conversion across an ordered URL sequence for the same visitor.

| param | type | description |
|---|---|---|
| `steps` | string | **required**, comma-separated URLs, 2–10 entries |
| `from`, `to` | unix-ms | optional |
| `event_type` | string | default `pageview` |

Response: `[{ step, url, visitors, dropoff_pct }]`. Visitors "reached"
step N if they have events for steps 1..N in increasing `ts` order and
all matched URLs exactly.

### `GET /stats/new_returning`

New vs returning visitor split over a time range. A visitor is "new" if
their earliest session falls inside the range; "returning" if older.

| param | type | description |
|---|---|---|
| `from`, `to` | unix-ms | default: last 24h |

Response: `{ new_visitors, returning_visitors, total_sessions }`.

### `DELETE /events` — GDPR right-to-be-forgotten

Admin-only. Deletes every event matching either a `user_id` **or** a
`visitor_hash`. Specifying both returns 400. Aggregates are recomputed
on the next materialization tick because the cursor is reset.

Header: `x-admin-key`.

| param | type | description |
|---|---|---|
| `user_id`      | string | attributed user |
| `visitor_hash` | string | anonymous visitor (requires `expose_visitor_hash` to know the hash) |

Response: `{ "deleted": <row_count> }`.

### `GET /export`

Stream every matching event. Same filters as `/events` except no `limit` /
`offset` — the response is a single streamed body. Semaphore-gated
(`server.export_concurrency`, default 2) so one slow reader can't starve the
SQLite pool.

| param | type | description |
|---|---|---|
| `format` | `ndjson` \| `csv` | default `ndjson` |
| `from`, `to`, `event_type`, `source`, `device_type`, `segment`, `url`, `user_id`, `country` | — | same semantics as `/events` |

- `ndjson`: `Content-Type: application/x-ndjson`, one JSON object per line.
- `csv`: `Content-Type: text/csv; charset=utf-8`, RFC-4180 header row.
  Formula-injection defense is applied to any cell starting with `=`, `+`,
  `@`, `-`, tab or CR: cells are pre-scrubbed and prefixed with an
  apostrophe. The header is stable — `visitor_hash` stays in the header
  even when `expose_visitor_hash=false` (the cell is empty).

Response streams. Export stops at `EXPORT_ROW_CAP` (5M rows) or
`server.export_deadline_secs` (default 60s), whichever comes first.

Errors: `401`, `429`, `503` when the concurrency semaphore is full.

---

## Webhooks

All webhook routes require `x-admin-key`.

### `POST /webhooks`

```json
{
  "url":         "https://downstream.example.com/hook",
  "secret":      "optional — used for HMAC signing, ≤ 256 B",
  "event_types": ["pageview", "search"]
}
```

`event_types` defaults to `["*"]`. Destination URL is validated up-front:
non-http(s) schemes, loopback/RFC-1918/link-local/CGNAT/cloud-metadata and
embedded userinfo are all rejected (opt-out via
`webhooks.allow_private_targets`). DNS is resolved and the resulting IPs
are pinned into the delivery client to defeat rebinding.

Response: `201 Created`, body:

```json
{
  "id": "9f7d...",
  "url": "https://downstream.example.com/hook",
  "has_secret": true,
  "event_types": ["pageview", "search"],
  "active": true,
  "created_at": 1745100000000
}
```

Secrets are write-only — the server never returns the secret back.

### `GET /webhooks` / `GET /webhooks/{id}`

List / fetch. Response shape matches `POST /webhooks`.

### `DELETE /webhooks/{id}`

`204 No Content` on success, `404` if the id doesn't exist. Cascades to
pending deliveries.

### Delivery protocol

For each matching event, the worker POSTs the full event JSON (same shape as
`/events` rows, including `user` if set) to the subscriber:

```
POST <webhook url>
Content-Type: application/json
User-Agent: simple-analytics/<version>
X-Analytics-Event-Id: <event id>
X-Analytics-Signature: blake3=<hex>   # only when the webhook has a secret
```

Signature construction (receiver-side verification):

```
key       = blake3_derive_key("simple-analytics webhook v1", secret_bytes)
signature = blake3_keyed(key, body_bytes).to_hex()
```

Retries: `retry_base_ms * 2^attempt` backoff up to `max_retries` (default 8).
After that the row is marked `failed` and no further attempts are made.
Each `(webhook_id, event_id)` is unique, so subscribers get every event at
most once across all retries.

Deliveries survive restarts (state is in `webhook_deliveries`), and a
shutdown signal triggers one last drain before the worker exits.

---

## User attribution

When `auth.user_signing_secret` is set, events may carry a signed `user`
object so the server trusts caller-supplied identity even from the public
browser path. The browser never sees the secret.

```text
sig_key = blake3_derive_key("simple-analytics user v1", secret)   → 32-byte key
user_sig = blake3_keyed(sig_key, user_json_bytes).to_hex()
```

The client sends:

- `user` — the **exact JSON bytes** the server signed, as a string.
- `user_sig` — 64 hex chars over those bytes.

The service re-hashes the bytes it received, constant-time-compares, rejects
on mismatch with `401`. On success, the decoded `id` goes into `user_id`
(indexed) and the full object into `user`. Both flow to `/events`,
`/stats/user_pages`, `/export` and webhook deliveries.

Reference generators:

- **Rust** — `simple_analytics::user_token::sign(secret, user_bytes)` is the
  canonical implementation; also used by
  `cargo run --example sign_user -- <secret> '<user json>'`.
- **PHP**:
  ```php
  $user     = json_encode(["id" => $uid, "plan" => $plan], JSON_UNESCAPED_SLASHES);
  $sig_key  = blake3_derive_key("simple-analytics user v1", $secret);
  $user_sig = bin2hex(blake3_keyed_hash($sig_key, $user));
  ```

Any unsigned / bad-signature / too-large `user` blob returns `401` with a
uniform error — no oracle on whether a secret is configured.

---

## Health & ops

- `GET /healthz` → `200 "ok"` always. Liveness only.
- `GET /readyz` → `200 "ready"` if a trivial DB round-trip succeeds, else
  `503 "not ready"`. Use for load-balancer drain signalling.
- `GET /metrics` → Prometheus text exposition (counters + gauges). No auth
  — put it behind the same VPN / firewall as `/readyz`.
- `GET /openapi.json` → the full OpenAPI 3.1 spec. Point
  `openapi-generator-cli` at it to generate clients in your language of
  choice.

### `SIGHUP` hot-reload

Sending `SIGHUP` to the process re-reads the config file and hot-swaps:

- `auth.write_keys` / `read_keys` / `admin_keys` — key rotation without
  dropping connections.
- `auth.allowed_origins` — add / remove browser domains.
- `ingest.allowed_segments` + `allow_unknown_segments`.

Everything else (DB path, listen address, endpoint paths) still needs
a restart. Reload failures (parse error, validation failure) leave the
running snapshot in place — look in the logs for the reason.

---

## URL validator contract

When `validator.url` is set, the service calls it once per unique URL (results
cached LRU for `cache_ttl_secs`).

```
GET {validator.url}?url=<percent-encoded target>
```

| status | meaning |
|---|---|
| `200` | URL is valid; event accepted |
| `404` | URL is invalid; event rejected with `400 invalid_url` |
| timeout / network / other | `fail_open=true` → accept; `false` → reject `400` |

Your endpoint can be anything that responds within `timeout_ms` —
a route-existence check against your sitemap is typical. The validator URL
itself is treated like a webhook target (SSRF defenses apply; opt-out via
`validator.allow_private_targets`).

---

## Source classification

Populated automatically at ingest. Priority:

1. `utm_source` (if the URL carries one). `google` / `bing` / `twitter` / … are
   mapped to canonical names; anything else passes through verbatim.
2. The `referer` header's host, classified against a small built-in
   allowlist (`hackernews`, `reddit`, `twitter`, `google`, `bing`, `duckduckgo`,
   `youtube`, `linkedin`, `facebook`, `instagram`, `tiktok`).
3. Fallback: `direct`.

The raw `referer` is stored unchanged so you can re-classify later.

---

## Data model cheatsheet

- `events` — raw log, append-only, indexed on `(ts)`, `(event_type, ts)`,
  `(visitor_hash, ts)`, `(source, ts)`, `(url, ts)`, partial `(user_id, ts)`,
  partial `(country, ts)`.
- `agg_daily` — rollup keyed by `(day, event_type, source, segment, device_type, country)`.
- `agg_daily_url` — rollup keyed by `(day, url, event_type)`.
- `webhooks` / `webhook_deliveries` — subscriber list + durable delivery
  queue.
- `daily_salts` — 32-byte random salt per UTC day for cookieless visitor
  hashing.
- `materialization_cursor` — last processed event id for the aggregates
  worker.

No ORM; all access goes through `sqlx` with parameterized queries.

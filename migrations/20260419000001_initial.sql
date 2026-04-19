-- Consolidated initial schema. The original migration set used the RENAME /
-- CREATE / DROP pattern to rebuild `agg_daily` and `webhook_deliveries` with
-- new columns and FK constraints; a rolling restart during migration could
-- deadlock the materialization cursor or the delivery worker. The service
-- has never been deployed, so we collapse everything into one clean forward
-- migration and never introduce that footgun.

-- Daily salts for cookieless visitor hashing. Rotated every 24h.
CREATE TABLE daily_salts (
    day_utc    TEXT PRIMARY KEY NOT NULL,
    salt       BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

-- Append-only event log. Raw events, never updated.
CREATE TABLE events (
    id             INTEGER PRIMARY KEY,
    ts             INTEGER NOT NULL,
    event_type     TEXT    NOT NULL,
    event_name     TEXT,
    url            TEXT    NOT NULL,
    page_title     TEXT,
    user_agent     TEXT    NOT NULL,
    device_type    TEXT,
    device_os      TEXT,
    device_browser TEXT,
    referer        TEXT,
    source         TEXT,
    utm_source     TEXT,
    utm_medium     TEXT,
    utm_campaign   TEXT,
    utm_term       TEXT,
    utm_content    TEXT,
    visitor_hash   TEXT    NOT NULL,
    segments       TEXT,
    extra          TEXT,
    -- Signed attribution. `user` is the full signed JSON blob; `user_id` is
    -- the decoded id, indexed for filter lookups. Both are NULL when the
    -- caller didn't supply attribution.
    user_id        TEXT,
    user           TEXT,
    country        TEXT,
    -- Sessions: group events by visitor_hash within an idle timeout.
    -- Assigned at ingest from `SessionAssigner` so queries don't need
    -- window functions. Always populated for new rows.
    session_id     TEXT
) STRICT;

CREATE INDEX idx_events_ts          ON events(ts);
CREATE INDEX idx_events_type_ts     ON events(event_type, ts);
CREATE INDEX idx_events_visitor_ts  ON events(visitor_hash, ts);
CREATE INDEX idx_events_source_ts   ON events(source, ts);
CREATE INDEX idx_events_url_ts      ON events(url, ts);
CREATE INDEX idx_events_device_ts   ON events(device_type, ts);
CREATE INDEX idx_events_user_ts     ON events(user_id, ts) WHERE user_id IS NOT NULL;
CREATE INDEX idx_events_country_ts  ON events(country, ts) WHERE country IS NOT NULL;
CREATE INDEX idx_events_session_ts
    ON events(session_id, ts)
    WHERE session_id IS NOT NULL;
CREATE INDEX idx_events_visitor_session
    ON events(visitor_hash, session_id)
    WHERE session_id IS NOT NULL;

-- Pre-computed daily rollups. Refreshed by the materialization worker.
-- `country` is part of the PK so dashboards can slice by geo.
CREATE TABLE agg_daily (
    day          TEXT    NOT NULL,
    event_type   TEXT    NOT NULL,
    source       TEXT    NOT NULL DEFAULT '',
    segment      TEXT    NOT NULL DEFAULT '',
    device_type  TEXT    NOT NULL DEFAULT '',
    country      TEXT    NOT NULL DEFAULT '',
    count        INTEGER NOT NULL,
    visitors     INTEGER NOT NULL,
    refreshed_at INTEGER NOT NULL,
    PRIMARY KEY (day, event_type, source, segment, device_type, country)
) STRICT;

CREATE INDEX idx_agg_day ON agg_daily(day);

-- Per-URL daily rollup. Separate table because URL cardinality is high and
-- we don't want it joining every /stats query.
CREATE TABLE agg_daily_url (
    day          TEXT    NOT NULL,
    url          TEXT    NOT NULL,
    event_type   TEXT    NOT NULL,
    count        INTEGER NOT NULL,
    visitors     INTEGER NOT NULL,
    refreshed_at INTEGER NOT NULL,
    PRIMARY KEY (day, url, event_type)
) STRICT;

CREATE INDEX idx_agg_url_day ON agg_daily_url(day);

-- Webhook subscribers.
CREATE TABLE webhooks (
    id          TEXT    PRIMARY KEY,
    url         TEXT    NOT NULL,
    secret      TEXT,
    event_types TEXT    NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL
) STRICT;

-- Persisted delivery queue with retry state.
-- `ON DELETE CASCADE` on webhook_id so deleting a subscriber cleanly drops
-- its pending queue without the caller seeing an FK violation.
CREATE TABLE webhook_deliveries (
    id           INTEGER PRIMARY KEY,
    webhook_id   TEXT    NOT NULL,
    event_id     INTEGER NOT NULL,
    -- 'pending' | 'in_progress' | 'delivered' | 'failed'
    status       TEXT    NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    next_attempt INTEGER NOT NULL,
    last_error   TEXT,
    last_status  INTEGER,
    created_at   INTEGER NOT NULL,
    delivered_at INTEGER,
    -- Timestamp the worker flipped this row to `in_progress`. Used by the
    -- stale-claim sweep to unstick rows whose worker died mid-flight.
    claimed_at   INTEGER,
    FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id)   REFERENCES events(id)
) STRICT;

CREATE INDEX idx_deliveries_pending
    ON webhook_deliveries(next_attempt)
    WHERE status = 'pending';

CREATE INDEX idx_deliveries_in_progress
    ON webhook_deliveries(claimed_at)
    WHERE status = 'in_progress';

-- Dedupe: a webhook subscriber should get each event at most once, even if
-- the enqueue loop double-fires after a crash.
CREATE UNIQUE INDEX idx_webhook_deliveries_unique
    ON webhook_deliveries(webhook_id, event_id);

-- Cursor used by the materialization / webhook workers to resume across
-- restarts.
CREATE TABLE materialization_cursor (
    name        TEXT PRIMARY KEY NOT NULL,
    last_id     INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;

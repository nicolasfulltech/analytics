#!/usr/bin/env bash
# Spin up a local simple-analytics instance with generous rate limits, run
# the load harness through a few scenarios, tear down. Results print to
# stdout.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

WRITE_KEY="$(openssl rand -hex 32)"
READ_KEY="$(openssl rand -hex 32)"
ADMIN_KEY="$(openssl rand -hex 32)"
SITE_TOKEN="$(openssl rand -hex 16)"
PORT="${PORT:-18080}"

cat > "$tmp/config.toml" <<EOF
[server]
bind               = "127.0.0.1:${PORT}"
max_body_bytes     = 65536
request_timeout_ms = 30000
export_concurrency   = 2
export_deadline_secs = 30

[database]
path            = "$tmp/analytics.db"
max_connections = 16

[auth]
write_keys      = ["$WRITE_KEY"]
read_keys       = ["$READ_KEY"]
admin_keys      = ["$ADMIN_KEY"]
site_token      = "$SITE_TOKEN"
allowed_origins = ["https://example.com"]

[ingest]
# Loosen limits for load-test baseline so we measure the service, not the limiter.
browser_rate_limit_per_min      = 600000
browser_rate_limit_burst        = 50000
beacon_token_rate_limit_per_min = 6000000
beacon_token_rate_limit_burst   = 500000
server_rate_limit_per_min       = 6000000
server_rate_limit_burst         = 500000
read_rate_limit_per_min         = 60000
read_rate_limit_burst           = 5000
# Loosened only for capacity measurement — in prod this caps per-IP abuse.
auth_ip_rate_limit_per_min      = 6000000
auth_ip_rate_limit_burst        = 500000
trust_proxy                     = false

[validator]
cache_ttl_secs = 60
cache_size     = 100
timeout_ms     = 500
fail_open      = true

[webhooks]
max_retries          = 3
retry_base_ms        = 100
concurrency          = 4
delivery_timeout_ms  = 5000
EOF

echo "== starting service on 127.0.0.1:${PORT} =="
CONFIG_PATH="$tmp/config.toml" \
RUST_LOG=warn \
"$here/target/release/simple-analytics" >"$tmp/server.log" 2>&1 &
PID=$!
trap 'kill -TERM $PID 2>/dev/null || true; rm -rf "$tmp"' EXIT

# wait for readiness
for _ in {1..30}; do
  if curl -fs "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

echo "== running scenarios =="

run_scenario() {
  local name="$1"
  local conc="$2"
  local dur="$3"
  echo
  echo "--- scenario=$name conc=$conc dur=${dur}s ---"
  "$here/target/release/examples/load_test" \
    --base "http://127.0.0.1:${PORT}" \
    --write-key "$WRITE_KEY" \
    --read-key "$READ_KEY" \
    --site-token "$SITE_TOKEN" \
    --origin "https://example.com" \
    --scenario "$name" \
    --concurrency "$conc" \
    --duration "$dur" \
    || true
}

run_scenario collect 32 5
run_scenario beacon  32 5
run_scenario events  16 5
run_scenario flood-bad-auth 32 3

# events count sanity (query DB directly — /events has limit<=1000)
events_total="$(sqlite3 "$tmp/analytics.db" 'SELECT COUNT(*) FROM events;' 2>/dev/null || echo '?')"
echo
echo "events table row count: $events_total"

# /readyz
echo -n "/readyz → "
curl -sw "HTTP %{http_code}  body=%{size_download}\n" -o /tmp/ready.body "http://127.0.0.1:${PORT}/readyz"

echo
echo "server log tail:"
tail -20 "$tmp/server.log" || true

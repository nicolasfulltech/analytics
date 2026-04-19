# Install

Docker only. For the HTTP contract see [API.md](./API.md).

## 1. Requirements

- Docker with `compose`.
- `openssl` (or any `rand` CLI) to generate keys.
- A reverse proxy (nginx, Caddy, Traefik) for TLS. Do not expose the container directly.

## 2. Generate keys

```sh
openssl rand -hex 32   # one each for WRITE_KEYS, READ_KEYS, ADMIN_KEYS
openssl rand -hex 16   # SITE_TOKEN (only if you use the browser beacon)
```

Keys are compared in constant time and multi-key is supported: to rotate, add
a new key, roll callers over, then remove the old one.

## 3. Run

```sh
git clone https://github.com/you/simple-analytics.git
cd simple-analytics

cat > .env <<EOF
ANALYTICS_WRITE_KEYS=$(openssl rand -hex 32)
ANALYTICS_READ_KEYS=$(openssl rand -hex 32)
ANALYTICS_ADMIN_KEYS=$(openssl rand -hex 32)
ANALYTICS_SITE_TOKEN=$(openssl rand -hex 16)
ANALYTICS_ALLOWED_ORIGINS=https://yoursite.com
EOF

docker compose up -d
```

Data lives in the named volume `analytics-data` (`/app/data` in the container).

## 4. Configure

Every setting is an env var, merged on top of built-in defaults. Full list in
[config.example.toml](./config.example.toml). The `compose` file wires the
common ones; extra keys can be added under `environment:` using the
`ANALYTICS_SECTION__KEY` format:

```yaml
environment:
  ANALYTICS_INGEST__TRUST_PROXY: "true"
  ANALYTICS_RETENTION__EVENTS_DAYS: "90"
  ANALYTICS_GEOIP__ENABLED: "true"
  ANALYTICS_GEOIP__DATABASE_PATH: /app/data/GeoLite2-Country.mmdb
```

Set `ANALYTICS_INGEST__TRUST_PROXY=true` only if there is exactly one proxy
hop in front. The service reads the last `X-Forwarded-For` value; multi-hop
chains would pick up an internal IP.

## 5. Reverse proxy

```nginx
server {
    listen 443 ssl http2;
    server_name analytics.example.com;

    ssl_certificate     /etc/letsencrypt/live/analytics.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/analytics.example.com/privkey.pem;

    client_max_body_size 128k;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 65s;
    }
}
```

## 6. Smoke test

```sh
curl -sS http://localhost:8080/healthz   # ok
curl -sS http://localhost:8080/readyz    # ready

curl -sS -X POST http://localhost:8080/collect \
  -H "content-type: application/json" \
  -H "x-write-key: $ANALYTICS_WRITE_KEYS" \
  -d '{"type":"pageview","url":"https://example.com/","user_agent":"Mozilla/5.0","ip":"203.0.113.10"}'

curl -sS "http://localhost:8080/events?limit=1" \
  -H "x-read-key: $ANALYTICS_READ_KEYS"
```

## 7. Browser snippet (optional)

With `SITE_TOKEN` and `ALLOWED_ORIGINS` set, drop this on your site:

```html
<script
  src="https://analytics.example.com/s.js"
  data-endpoint="https://analytics.example.com/e"
  data-site-token="YOUR_PUBLIC_SITE_TOKEN"
  defer
></script>
```

See [API.md](./API.md#browser-snippet) for the full surface.

## 8. Update

Migrations are forward-only and run at startup. Take a backup first on major
upgrades.

```sh
cd simple-analytics
git pull
docker compose build --pull
docker compose up -d
```

If you pin a published image instead of building locally:

```sh
docker compose pull
docker compose up -d
```

Check it started:

```sh
docker compose logs -f analytics
curl -sS http://localhost:8080/readyz
```

Roll back by checking out the previous tag and running the same commands.

## 9. Backup

SQLite WAL mode is safe to back up live. Snapshot the volume from the host:

```sh
docker run --rm -v analytics-data:/d -v "$PWD":/b alpine \
  tar -C /d -czf /b/analytics-$(date +%F).tar.gz .
```

Or use the built-in backup worker (periodic `VACUUM INTO`):

```yaml
environment:
  ANALYTICS_BACKUP__PATH: /app/data/backups
  ANALYTICS_BACKUP__INTERVAL_HOURS: "24"
  ANALYTICS_BACKUP__KEEP_COUNT: "7"
```

The DB holds webhook secrets and visitor hashes. Keep backups encrypted and
access-restricted. If a backup leaks, rotate webhook secrets.

## 10. Uninstall

```sh
docker compose down -v   # -v wipes the SQLite volume. Back it up first.
```

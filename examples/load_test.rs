//! Load / soak tester for simple-analytics.
//!
//! Fires a chosen scenario against a running instance and reports throughput,
//! latency percentiles, and error-code breakdown. Uses reqwest with a shared
//! connection pool so we actually measure the server, not TLS handshakes.
//!
//! Usage:
//!   cargo run --release --example load_test -- \
//!       --base http://127.0.0.1:8080 \
//!       --write-key $WRITE \
//!       --read-key $READ \
//!       --site-token $TOK \
//!       --origin https://example.com \
//!       --scenario collect \
//!       --concurrency 64 \
//!       --duration 30
//!
//! Scenarios: collect | beacon | events | export | mixed | flood-bad-auth
//!
//! Baselines (defaults, single node, local DB):
//!   collect     → ~500 rps sustained per write key (server_rate_limit_burst)
//!   beacon      → 60k/min aggregated (beacon_token_rate_limit)
//!   events      → 120/min per read key (read_rate_limit)
//!   export      → 2 concurrent, each up to 60s
//!   mixed       → legitimate blend — should NOT see 5xx

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::{Client, Method, StatusCode};
use serde_json::json;

#[derive(Debug, Clone)]
struct Args {
    base: String,
    write_key: Option<String>,
    read_key: Option<String>,
    site_token: Option<String>,
    origin: String,
    scenario: String,
    concurrency: usize,
    duration_secs: u64,
    beacon_path: String,
    browser_token_header: String,
}

impl Args {
    fn from_env() -> Self {
        let mut a = Args {
            base: "http://127.0.0.1:8080".into(),
            write_key: std::env::var("WRITE_KEY").ok(),
            read_key: std::env::var("READ_KEY").ok(),
            site_token: std::env::var("SITE_TOKEN").ok(),
            origin: "https://example.com".into(),
            scenario: "collect".into(),
            concurrency: 16,
            duration_secs: 10,
            beacon_path: "/e".into(),
            browser_token_header: "x-id".into(),
        };
        let mut it = std::env::args().skip(1);
        while let Some(k) = it.next() {
            let v = it.next().unwrap_or_default();
            match k.as_str() {
                "--base" => a.base = v,
                "--write-key" => a.write_key = Some(v),
                "--read-key" => a.read_key = Some(v),
                "--site-token" => a.site_token = Some(v),
                "--origin" => a.origin = v,
                "--scenario" => a.scenario = v,
                "--concurrency" => a.concurrency = v.parse().unwrap_or(16),
                "--duration" => a.duration_secs = v.parse().unwrap_or(10),
                "--beacon-path" => a.beacon_path = v,
                "--browser-token-header" => a.browser_token_header = v,
                "--help" | "-h" => {
                    eprintln!("{}", HELP);
                    std::process::exit(0);
                }
                _ => eprintln!("unknown flag: {k}"),
            }
        }
        a
    }
}

const HELP: &str = "\
simple-analytics load tester

flags:
  --base URL                 default http://127.0.0.1:8080
  --write-key KEY            server ingest key (for collect / mixed)
  --read-key KEY             read key (for events / export)
  --site-token TOK           browser beacon token
  --origin URL               default https://example.com
  --scenario NAME            collect | beacon | events | export | mixed | flood-bad-auth
  --concurrency N            default 16
  --duration SECS            default 10
  --beacon-path PATH         default /e
  --browser-token-header H   default x-id
";

#[derive(Default)]
struct Stats {
    total: AtomicU64,
    status: Mutex<HashMap<u16, u64>>,
    latencies_us: Mutex<Vec<u64>>,
}

impl Stats {
    fn record(&self, status: StatusCode, elapsed: Duration) {
        self.total.fetch_add(1, Ordering::Relaxed);
        let us = elapsed.as_micros() as u64;
        self.latencies_us.lock().unwrap().push(us);
        *self
            .status
            .lock()
            .unwrap()
            .entry(status.as_u16())
            .or_insert(0) += 1;
    }

    fn report(&self, duration: Duration) {
        let total = self.total.load(Ordering::Relaxed);
        let rps = total as f64 / duration.as_secs_f64();
        let status = self.status.lock().unwrap();
        let mut lat = self.latencies_us.lock().unwrap();
        lat.sort_unstable();

        let p = |q: f64| -> u64 {
            if lat.is_empty() {
                return 0;
            }
            let idx = ((lat.len() as f64) * q) as usize;
            lat[idx.min(lat.len() - 1)]
        };

        println!("\n=== results ===");
        println!("duration   : {:.1}s", duration.as_secs_f64());
        println!("requests   : {total}");
        println!("throughput : {rps:.1} req/s");
        println!(
            "latency us : p50={} p90={} p95={} p99={} max={}",
            p(0.50),
            p(0.90),
            p(0.95),
            p(0.99),
            lat.last().copied().unwrap_or(0)
        );
        println!("status code breakdown:");
        let mut codes: Vec<_> = status.iter().collect();
        codes.sort();
        for (code, n) in codes {
            println!("  {code} → {n}");
        }
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    let client = Arc::new(
        Client::builder()
            .pool_max_idle_per_host(args.concurrency * 2)
            .timeout(Duration::from_secs(60))
            .build()?,
    );
    let stats = Arc::new(Stats::default());
    let deadline = Instant::now() + Duration::from_secs(args.duration_secs);
    let started = Instant::now();

    let mut handles = Vec::with_capacity(args.concurrency);
    for worker_id in 0..args.concurrency {
        let client = client.clone();
        let stats = stats.clone();
        let args = args.clone();
        handles.push(tokio::spawn(async move {
            let mut i: u64 = 0;
            while Instant::now() < deadline {
                let start = Instant::now();
                let result = match args.scenario.as_str() {
                    "collect" => send_collect(&client, &args, worker_id, i).await,
                    "beacon" => send_beacon(&client, &args, worker_id, i).await,
                    "events" => send_events(&client, &args).await,
                    "export" => send_export(&client, &args).await,
                    "mixed" => match i % 10 {
                        0..=7 => send_collect(&client, &args, worker_id, i).await,
                        8 => send_events(&client, &args).await,
                        _ => send_beacon(&client, &args, worker_id, i).await,
                    },
                    "flood-bad-auth" => send_bad_auth(&client, &args).await,
                    other => {
                        eprintln!("unknown scenario: {other}");
                        return;
                    }
                };
                let elapsed = start.elapsed();
                match result {
                    Ok(status) => stats.record(status, elapsed),
                    Err(e) => {
                        // treat transport errors as 599 — visible in the breakdown
                        stats.record(StatusCode::from_u16(599).unwrap(), elapsed);
                        if i < 3 {
                            eprintln!("worker {worker_id} req {i} error: {e}");
                        }
                    }
                }
                i += 1;
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    stats.report(started.elapsed());
    Ok(())
}

async fn send_collect(
    client: &Client,
    args: &Args,
    worker_id: usize,
    i: u64,
) -> anyhow::Result<StatusCode> {
    let key = args
        .write_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--write-key required"))?;
    let body = json!({
        "type": "pageview",
        "url": format!("https://example.com/w{worker_id}/i{i}"),
        "title": "load test",
        "referer": null,
        "segments": ["free"],
        "user_agent": "Mozilla/5.0 (loadtest)",
        "ip": format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff),
    });
    let resp = client
        .request(Method::POST, format!("{}/collect", args.base))
        .header("content-type", "application/json")
        .header("x-write-key", key)
        .json(&body)
        .send()
        .await?;
    Ok(resp.status())
}

async fn send_beacon(
    client: &Client,
    args: &Args,
    worker_id: usize,
    i: u64,
) -> anyhow::Result<StatusCode> {
    let tok = args
        .site_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--site-token required"))?;
    let body = json!({
        "type": "pageview",
        "url": format!("https://example.com/beacon/w{worker_id}/i{i}"),
        "title": "load test",
        "referer": null,
        "segments": [],
    });
    let resp = client
        .request(Method::POST, format!("{}{}", args.base, args.beacon_path))
        .header("content-type", "application/json")
        .header(args.browser_token_header.as_str(), tok)
        .header("origin", &args.origin)
        .header("user-agent", "Mozilla/5.0 (loadtest)")
        .json(&body)
        .send()
        .await?;
    Ok(resp.status())
}

async fn send_events(client: &Client, args: &Args) -> anyhow::Result<StatusCode> {
    let key = args
        .read_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--read-key required"))?;
    let resp = client
        .get(format!("{}/events?limit=10", args.base))
        .header("x-read-key", key)
        .send()
        .await?;
    Ok(resp.status())
}

async fn send_export(client: &Client, args: &Args) -> anyhow::Result<StatusCode> {
    let key = args
        .read_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--read-key required"))?;
    let mut resp = client
        .get(format!("{}/export?format=ndjson", args.base))
        .header("x-read-key", key)
        .send()
        .await?;
    // Drain the stream so the server's backpressure path is exercised and
    // the SQLite connection is actually released.
    while resp.chunk().await?.is_some() {}
    Ok(resp.status())
}

async fn send_bad_auth(client: &Client, args: &Args) -> anyhow::Result<StatusCode> {
    // Baseline DoS probe — everything below should 401 instantly and not
    // consume DB connections or grow memory.
    let resp = client
        .request(Method::POST, format!("{}/collect", args.base))
        .header("content-type", "application/json")
        .header("x-write-key", "this-is-not-a-valid-key-at-all-not-real")
        .body(
            "{\"type\":\"pageview\",\"url\":\"https://x\",\"user_agent\":\"a\",\"ip\":\"1.1.1.1\"}",
        )
        .send()
        .await?;
    Ok(resp.status())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() -> anyhow::Result<()> {
    let args = Args::from_env();
    println!(
        "loadtest: scenario={} conc={} duration={}s base={}",
        args.scenario, args.concurrency, args.duration_secs, args.base
    );
    run(args).await
}

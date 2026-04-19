//! End-to-end read-path benchmarks.
//!
//! Builds an in-memory SQLite pool, seeds a few thousand events, and
//! measures how long the common query endpoints take. These numbers are
//! only meaningful relative to each other (no TCP, no disk WAL), but
//! regressions show up as clear percentage deltas.

use criterion::{Criterion, criterion_group, criterion_main};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};

const ROW_COUNT: usize = 5_000;

async fn seed(pool: &SqlitePool) {
    // Batch inserts via one `QueryBuilder` — faster than a loop, and the
    // shape we care about for benchmarking is the read side anyway.
    let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
        "INSERT INTO events (ts, event_type, url, user_agent, visitor_hash, session_id) ",
    );
    qb.push_values(0..ROW_COUNT, |mut row, i| {
        row.push_bind((i as i64) * 1000)
            .push_bind("pageview")
            .push_bind(format!("https://example.com/p/{}", i % 100))
            .push_bind("Mozilla/5.0")
            .push_bind(format!("vh-{}", i % 500))
            .push_bind(format!("s-{}", i % 1000));
    });
    qb.build().execute(pool).await.unwrap();
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn bench_queries(c: &mut Criterion) {
    let rt = runtime();
    let pool = rt.block_on(async {
        let p = simple_analytics::db::in_memory_for_tests().await.unwrap();
        seed(&p).await;
        p
    });

    c.bench_function("stats_pages_5k_rows", |b| {
        b.to_async(&rt).iter(|| async {
            let row: (String, i64) = sqlx::query_as(
                "SELECT url, COUNT(*) AS c
                 FROM events WHERE event_type = 'pageview'
                 GROUP BY url ORDER BY c DESC LIMIT 1",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            row
        });
    });

    c.bench_function("stats_sources_5k_rows", |b| {
        b.to_async(&rt).iter(|| async {
            let _rows: Vec<(Option<String>, i64)> =
                sqlx::query_as("SELECT source, COUNT(*) FROM events GROUP BY source LIMIT 10")
                    .fetch_all(&pool)
                    .await
                    .unwrap();
        });
    });

    c.bench_function("timeseries_hour_5k_rows", |b| {
        b.to_async(&rt).iter(|| async {
            let _rows: Vec<(String, i64)> = sqlx::query_as(
                "SELECT strftime('%Y-%m-%dT%H:00:00Z', ts/1000, 'unixepoch') AS b, COUNT(*)
                 FROM events GROUP BY b ORDER BY b ASC LIMIT 100",
            )
            .fetch_all(&pool)
            .await
            .unwrap();
        });
    });
}

criterion_group!(benches, bench_queries);
criterion_main!(benches);

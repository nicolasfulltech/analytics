//! Ingestion-path micro-benchmarks.
//!
//! These measure the pure per-event work: UA parse, UTM parse, source
//! classify, visitor hashing. They do NOT include the HTTP stack or SQLite
//! insert — the `queries` bench covers the DB side. A regression here
//! usually means a new allocator / new regex / unintended clone.

use blake3::hash;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use simple_analytics::ingest::parse;

fn bench_parse_user_agent(c: &mut Criterion) {
    let uas = [
        (
            "safari-mac",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        ),
        (
            "chrome-win",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        ),
        (
            "firefox-lin",
            "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
        ),
        (
            "ios-iphone",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        ),
        (
            "bot-google",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
        ),
    ];
    let mut group = c.benchmark_group("parse_user_agent");
    for (name, ua) in uas {
        group.bench_with_input(BenchmarkId::from_parameter(name), ua, |b, ua| {
            b.iter(|| parse::parse_user_agent(ua));
        });
    }
    group.finish();
}

fn bench_parse_utm(c: &mut Criterion) {
    let urls = [
        ("no-utm", "https://example.com/pricing"),
        ("one-utm", "https://example.com/pricing?utm_source=hn"),
        (
            "full-utm",
            "https://example.com/pricing?utm_source=google&utm_medium=cpc&utm_campaign=launch&utm_term=analytics&utm_content=ad1",
        ),
        (
            "garbage",
            "https://example.com/x?a=1&b=2&c=3&utm_source=&utm_medium=%E2%9C%93",
        ),
    ];
    let mut group = c.benchmark_group("parse_utm");
    for (name, url) in urls {
        group.bench_with_input(BenchmarkId::from_parameter(name), url, |b, url| {
            b.iter(|| parse::parse_utm(url));
        });
    }
    group.finish();
}

fn bench_classify_source(c: &mut Criterion) {
    let cases = [
        ("no-ref", ("https://example.com/", None::<&str>)),
        (
            "hn",
            (
                "https://example.com/",
                Some("https://news.ycombinator.com/"),
            ),
        ),
        (
            "twitter",
            ("https://example.com/", Some("https://t.co/abc")),
        ),
        ("utm", ("https://example.com/?utm_source=mail", None)),
    ];
    let mut group = c.benchmark_group("classify_source");
    for (name, (url, referer)) in cases {
        let utm = parse::parse_utm(url);
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(utm, referer),
            |b, (utm, r)| {
                b.iter(|| parse::classify_source(utm, *r));
            },
        );
    }
    group.finish();
}

fn bench_visitor_hash(c: &mut Criterion) {
    // Proxy bench — exercises the same blake3-keyed path the service uses
    // without setting up a SaltStore. `visitor::visitor_hash` does the real
    // work; here we bench blake3::hash over a similar input size.
    let ip = "203.0.113.10";
    let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15";
    c.bench_function("hash_ip_ua_concat", |b| {
        let mut buf = Vec::with_capacity(ip.len() + 1 + ua.len());
        b.iter(|| {
            buf.clear();
            buf.extend_from_slice(ip.as_bytes());
            buf.push(0);
            buf.extend_from_slice(ua.as_bytes());
            hash(&buf)
        });
    });
}

criterion_group!(
    benches,
    bench_parse_user_agent,
    bench_parse_utm,
    bench_classify_source,
    bench_visitor_hash,
);
criterion_main!(benches);

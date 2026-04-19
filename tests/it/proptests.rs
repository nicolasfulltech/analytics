//! Property-based tests.
//!
//! proptest generates many inputs from the declared strategy and shrinks
//! failures down to a minimal reproducer. We use it for two things that
//! would be painful to cover exhaustively with hand-written cases:
//!
//! 1. `push_filters` — for any combination of filter fields, the resulting
//!    SQL must parse and execute without error against the real schema.
//!    Catches quoting / placeholder-count bugs the unit tests miss.
//! 2. `Config::validate` — bounded random origin / path / header values
//!    must never panic. Any validation result is fine as long as it's not
//!    a crash.

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use simple_analytics::config::{AuthConfig, Config, EndpointsConfig};
use simple_analytics::query::{EventFilters, push_filters};
use sqlx::{QueryBuilder, Sqlite};

fn arb_optional_string() -> impl Strategy<Value = Option<String>> {
    prop::option::of(
        // Strings that can legitimately hit filter fields. Includes chars
        // that would break naive SQL string interpolation — push_bind has
        // to keep them safe.
        "[a-zA-Z0-9 _'\";%\\-]{0,64}".prop_map(String::from),
    )
}

fn arb_filters() -> impl Strategy<Value = EventFilters> {
    (
        prop::option::of(any::<i64>()),
        prop::option::of(any::<i64>()),
        arb_optional_string(),
        arb_optional_string(),
        arb_optional_string(),
        arb_optional_string(),
        arb_optional_string(),
        arb_optional_string(),
        arb_optional_string(),
        prop::option::of(0i64..1_000),
        prop::option::of(0i64..1_000),
    )
        .prop_map(
            |(
                from,
                to,
                event_type,
                source,
                device_type,
                segment,
                url,
                user_id,
                country,
                limit,
                offset,
            )| EventFilters {
                from,
                to,
                event_type,
                source,
                device_type,
                segment,
                url,
                user_id,
                country,
                limit,
                offset,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn push_filters_builds_valid_sql(f in arb_filters()) {
        // Smoke: constructing a QueryBuilder + push_filters never panics,
        // no matter how exotic the strings are. The actual SQL safety
        // comes from push_bind — verified indirectly because we run the
        // query against the DB in the next test.
        let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
            "SELECT COUNT(*) FROM events WHERE 1=1",
        );
        push_filters(&mut qb, &f);
        let _sql = qb.sql();
    }
}

#[tokio::test]
async fn push_filters_executes_against_real_schema() {
    // Build an in-memory pool and run a handful of generated filter sets
    // through real SQLite. If any combination produces malformed SQL the
    // fetch_all will error; we assert Ok.
    let pool = simple_analytics::db::in_memory_for_tests().await.unwrap();

    let mut runner = proptest::test_runner::TestRunner::default();
    for _ in 0..32 {
        let value = arb_filters().new_tree(&mut runner).unwrap().current();
        let mut qb: QueryBuilder<Sqlite> =
            QueryBuilder::new("SELECT COUNT(*) FROM events WHERE 1=1");
        push_filters(&mut qb, &value);
        let result: sqlx::Result<i64> = qb.build_query_scalar().fetch_one(&pool).await;
        assert!(
            result.is_ok(),
            "filter combo produced invalid SQL: {result:?}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn config_validate_never_panics_on_random_endpoint_values(
        path in "\\PC{0,80}",
        header in "\\PC{0,80}",
        ns in "\\PC{0,80}",
    ) {
        let mut c = Config {
            server: Default::default(),
            database: Default::default(),
            auth: AuthConfig {
                write_keys: vec!["a".repeat(32)],
                read_keys: vec!["b".repeat(32)],
                admin_keys: vec!["c".repeat(32)],
                site_token: String::new(),
                allowed_origins: vec![],
                user_signing_secret: String::new(),
                admin_ip_allowlist: vec![],
                user_token_max_age_secs: 900,
            },
            ingest: Default::default(),
            validator: Default::default(),
            webhooks: Default::default(),
            materialization: Default::default(),
            sessions: Default::default(),
            backup: Default::default(),
            endpoints: EndpointsConfig::default(),
            geoip: Default::default(),
            privacy: Default::default(),
            retention: Default::default(),
        };
        c.endpoints.browser_collect_path = path;
        c.endpoints.browser_token_header = header;
        c.endpoints.js_namespace = ns;
        // A panic here is a real bug; a validation error is fine. We just
        // want to verify the function is total.
        let _ = c.validate();
    }
}

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use moka::future::Cache;

/// Per-key token bucket rate limiter.
///
/// Tokens refill at `rate_per_min` per minute, up to `burst` tokens outstanding.
/// Keys are evicted after 10 minutes of inactivity so the cache size stays bounded
/// even under high cardinality (e.g. many unique IPs).
pub struct RateLimiter {
    cache: Cache<String, Arc<Bucket>>,
    rate_per_sec: f64,
    burst: f64,
}

struct Bucket {
    state: Mutex<BucketState>,
}

struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(rate_per_min: u32, burst: u32) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(100_000)
                // `time_to_idle` (not `time_to_live`) so an abuser who idles
                // across the TTL boundary doesn't silently get a brand-new
                // `burst` refresh. TTI resets on every access, so an active
                // caller keeps the same bucket across the whole window.
                .time_to_idle(Duration::from_secs(600))
                .build(),
            rate_per_sec: f64::from(rate_per_min.max(1)) / 60.0,
            burst: f64::from(burst.max(1)),
        }
    }

    pub async fn check(&self, key: &str) -> bool {
        let bucket = self
            .cache
            .get_with(key.to_string(), async {
                Arc::new(Bucket {
                    state: Mutex::new(BucketState {
                        tokens: self.burst,
                        last_refill: Instant::now(),
                    }),
                })
            })
            .await;

        // Recover from a poisoned mutex instead of cascading panics across
        // every subsequent request for the same key. A poisoned state is still
        // a valid token-bucket value; we just lost the guarantee that the
        // previous holder finished their update cleanly.
        let mut state = bucket
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.rate_per_sec).min(self.burst);
        state.last_refill = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn burst_allows_up_to_burst_then_denies() {
        let rl = RateLimiter::new(60, 3);
        assert!(rl.check("ip").await);
        assert!(rl.check("ip").await);
        assert!(rl.check("ip").await);
        assert!(!rl.check("ip").await);
    }

    #[tokio::test]
    async fn different_keys_do_not_share_bucket() {
        let rl = RateLimiter::new(60, 1);
        assert!(rl.check("a").await);
        assert!(rl.check("b").await);
        assert!(!rl.check("a").await);
        assert!(!rl.check("b").await);
    }

    #[tokio::test]
    async fn tokens_refill_over_time() {
        let rl = RateLimiter::new(6_000, 1); // 100 per second
        assert!(rl.check("k").await);
        assert!(!rl.check("k").await);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(rl.check("k").await);
    }
}

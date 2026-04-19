//! Fuzz target: URL parsing + UTM extraction + source classification.
//!
//! These run on every inbound event and operate on attacker-supplied URLs
//! and referers. A panic here is an ingestion DoS.

#![no_main]

use libfuzzer_sys::fuzz_target;
use simple_analytics::ingest::parse;

fuzz_target!(|data: &[u8]| {
    // Split the corpus into (url, referer) by the first NUL byte — gives
    // the fuzzer independent axes to explore without needing a structured
    // Arbitrary impl.
    let (url_bytes, ref_bytes) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };

    let url = match std::str::from_utf8(url_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };
    let referer = std::str::from_utf8(ref_bytes).ok();

    let utm = parse::parse_utm(url);
    let _ = parse::classify_source(&utm, referer);
});

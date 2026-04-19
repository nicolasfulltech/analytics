//! Fuzz target: deserialize arbitrary bytes as an `IncomingEvent`.
//!
//! `/collect` accepts caller-supplied JSON; anything that can panic or
//! hang in the parser needs to show up here rather than on the hot path.
//! Success (valid parse) is uninteresting — the harness just exits.
//! A panic is a real bug; cargo-fuzz will minimize the input and keep it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use simple_analytics::model::IncomingEvent;

fuzz_target!(|data: &[u8]| {
    // Both the raw-byte and utf8 paths matter — the real endpoint feeds
    // through serde_json which enforces utf-8, but JSON parsers have had
    // plenty of historical bugs around invalid encodings.
    let _ = serde_json::from_slice::<IncomingEvent>(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<IncomingEvent>(s);
    }
});

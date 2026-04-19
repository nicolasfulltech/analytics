//! Small crypto / constant-time helpers shared between auth paths.

/// Byte-for-byte equality in constant time. Returns `false` on length mismatch
/// without short-circuiting character comparison. Safe for comparing MAC tags
/// where both operands are the same fixed length.
///
/// Do NOT pass inputs of attacker-controlled length directly — a length
/// mismatch still leaks the length through branch timing. Hash both sides to
/// a fixed width first (see [`fixed_digest`]).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    // All current callers pre-hash both sides to 32 bytes; a future caller
    // that forgets would reintroduce the length-timing oracle documented
    // above. Fail loudly in debug so tests catch it immediately.
    debug_assert_eq!(
        a.len(),
        b.len(),
        "ct_eq inputs must match in length; hash to a fixed digest first"
    );
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    // `black_box` prevents LLVM from short-circuiting the XOR loop once it
    // proves `acc != 0` early — with `lto = "thin"` in release builds the
    // optimizer can see across crate boundaries and would otherwise be free
    // to turn this into a variable-time comparison.
    core::hint::black_box(acc) == 0
}

/// Key-separation context for API-key comparisons. Feed candidate + each
/// configured key through blake3-keyed with this context so we always compare
/// 32 fixed bytes regardless of the operator's key length.
pub const API_KEY_CONTEXT: &str = "simple-analytics api key compare v1";

/// Deterministic 32-byte fingerprint of `data`, scoped by a domain-separation
/// context. Used to make key comparisons fixed-width; not a substitute for
/// storing the key.
///
/// `derive_key(context, ...)` already binds the context to the resulting key,
/// so we don't need to re-hash the context into the body — that was redundant
/// domain separation. Keep the function to the minimal, unambiguous shape.
pub fn fixed_digest(context: &str, data: &[u8]) -> [u8; 32] {
    let key = blake3::derive_key(context, b"fingerprint");
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(data);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        // length-mismatch path debug_asserts; we rely on callers to
        // pre-hash. Test a zero-length pair just to exercise the tight-loop.
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn digest_stable() {
        let a = fixed_digest("ctx", b"alpha");
        let b = fixed_digest("ctx", b"alpha");
        assert_eq!(a, b);
    }

    #[test]
    fn digest_changes_with_context() {
        let a = fixed_digest("ctx-a", b"same");
        let b = fixed_digest("ctx-b", b"same");
        assert_ne!(a, b);
    }
}

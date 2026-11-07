//! SHA-1 (FIPS 180-4), used solely for the RFC 6960 ResponderID `byKey` KeyHash comparison.
//!
//! The standard fixes KeyHash to SHA-1; the comparison is an identity match, not a security
//! primitive. It is implemented here to avoid adding a `sha1` dependency for one call.

/// The SHA-1 initial hash value (FIPS 180-4 §5.3.1).
const INITIAL_STATE: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

/// The SHA-1 digest of `data`.
pub(super) fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let mut state = INITIAL_STATE;
    for block in padded(data).as_chunks::<64>().0 {
        compress(&mut state, block);
    }
    let mut digest = [0u8; 20];
    for (slot, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *slot = word.to_be_bytes();
    }
    digest
}

/// `data` followed by the `0x80` terminator, zero fill to 56 mod 64, and the bit length as
/// a big-endian `u64` (FIPS 180-4 §5.1.1).
fn padded(data: &[u8]) -> Vec<u8> {
    let bit_length = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());
    message
}

/// The 80-word message schedule of one 64-byte block (FIPS 180-4 §6.1.2 step 1).
fn message_schedule(block: &[u8; 64]) -> [u32; 80] {
    let mut w = [0u32; 80];
    for (slot, word) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *slot = u32::from_be_bytes(*word);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    w
}

/// The round function and constant of round `round` (FIPS 180-4 §4.1.1, §4.2.1).
fn round_function(round: usize, b: u32, c: u32, d: u32) -> (u32, u32) {
    match round {
        0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
        20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
        40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
        _ => (b ^ c ^ d, 0xCA62_C1D6),
    }
}

/// Fold one 64-byte block into `state` (FIPS 180-4 §6.1.2 steps 2-4).
fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (round, &word) in message_schedule(block).iter().enumerate() {
        let (f, k) = round_function(round, b, c, d);
        let next = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = next;
    }
    for (slot, delta) in state.iter_mut().zip([a, b, c, d, e]) {
        *slot = slot.wrapping_add(delta);
    }
}

#[cfg(test)]
mod tests {
    use super::sha1_hash;

    /// Decode a 40-char hex string into the 20-byte SHA-1 digest array.
    fn hex20(s: &str) -> [u8; 20] {
        let bytes = s.as_bytes();
        let mut out = [0u8; 20];
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = (bytes[i * 2] as char).to_digit(16).expect("hex hi") as u8;
            let lo = (bytes[i * 2 + 1] as char).to_digit(16).expect("hex lo") as u8;
            *slot = (hi << 4) | lo;
        }
        out
    }

    /// Known-answer vectors for the hand-rolled FIPS 180-4 SHA-1 used by the
    /// ResponderID `byKey` match (the standard fixes KeyHash to SHA-1). Guards the
    /// local implementation against a regression that would make a legitimate
    /// byKey responder mismatch (fail closed).
    #[test]
    fn sha1_known_answer_vectors() {
        // FIPS 180-4 / RFC 3174 published test vectors.
        for (input, expected, label) in [
            (
                &b""[..],
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "SHA-1 of empty input",
            ),
            (
                b"abc",
                "a9993e364706816aba3e25717850c26c9cd0d89d",
                "SHA-1(\"abc\")",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
                "SHA-1 of the 56-byte FIPS multi-block vector",
            ),
        ] {
            assert_eq!(sha1_hash(input), hex20(expected), "{label}");
        }
    }
}

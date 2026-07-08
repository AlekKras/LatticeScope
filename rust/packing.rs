//! Coefficient packing that mirrors the ML-KEM / ML-DSA serialisation layouts.
//!
//! A single generic little-endian `d`-bit packer covers Kyber's raw 12-bit
//! `poly_frombytes` layout, its compressed `du`/`dv` widths, and Dilithium's
//! `t0`/`t1` widths. The byte layout matches the mock target's 12-bit unpacker
//! exactly (bit 0 of coefficient 0 → bit 0 of byte 0), which is what lets a
//! structure-aware mutation land a specific out-of-range coefficient on a
//! specific byte.

pub const KYBER_N: usize = 256;
pub const KYBER_Q: u32 = 3329;
pub const DILITHIUM_N: usize = 256;
pub const DILITHIUM_Q: u32 = 8_380_417;

#[inline]
fn mask(d: u32) -> u64 {
    if d >= 64 {
        u64::MAX
    } else {
        (1u64 << d) - 1
    }
}

/// Pack coefficients little-endian, `d` bits each, masking each to `d` bits.
/// Masking (rather than rejecting) is deliberate: it models the out-of-range
/// and negative-wrap values a real serialiser might be handed.
pub fn pack_bits(coeffs: &[u32], d: u32) -> Vec<u8> {
    let total_bits = coeffs.len() * d as usize;
    let mut out = vec![0u8; (total_bits + 7) / 8];
    let m = mask(d);
    let mut bitpos = 0usize;
    for &c in coeffs {
        let v = (c as u64) & m;
        for b in 0..d as usize {
            if (v >> b) & 1 == 1 {
                out[bitpos >> 3] |= 1u8 << (bitpos & 7);
            }
            bitpos += 1;
        }
    }
    out
}

/// Inverse of [`pack_bits`] (used by round-trip tests).
pub fn unpack_bits(data: &[u8], d: u32, n: usize) -> Vec<u32> {
    let mut out = vec![0u32; n];
    let mut bitpos = 0usize;
    for slot in out.iter_mut() {
        let mut v = 0u64;
        for b in 0..d as usize {
            let byte = bitpos >> 3;
            let bit = bitpos & 7;
            if byte < data.len() && (data[byte] >> bit) & 1 == 1 {
                v |= 1u64 << b;
            }
            bitpos += 1;
        }
        *slot = v as u32;
    }
    out
}

/// Kyber `Compress_q(x, d)` = round(2^d / q · x) mod 2^d.
pub fn compress(x: u32, d: u32, q: u32) -> u32 {
    let q = q as u64;
    let num = ((x as u64) << d) + q / 2;
    ((num / q) & mask(d)) as u32
}

/// Kyber `Decompress_q(y, d)` = round(q / 2^d · y).
pub fn decompress(y: u32, d: u32, q: u32) -> u32 {
    let num = (y as u64) * (q as u64) + (1u64 << (d - 1));
    (num >> d) as u32
}

/// Kyber `poly_tobytes` width.
pub fn kyber_poly_bits() -> u32 {
    12
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip_12bit() {
        let coeffs: Vec<u32> = (0..KYBER_N as u32).map(|i| (i * 13) % KYBER_Q).collect();
        let bytes = pack_bits(&coeffs, 12);
        assert_eq!(bytes.len(), KYBER_N * 12 / 8); // 384
        let back = unpack_bits(&bytes, 12, KYBER_N);
        assert_eq!(coeffs, back);
    }

    #[test]
    fn pack_unpack_roundtrip_23bit() {
        let coeffs: Vec<u32> = (0..DILITHIUM_N as u32)
            .map(|i| (i * 97 + 5) % DILITHIUM_Q)
            .collect();
        let bytes = pack_bits(&coeffs, 23);
        let back = unpack_bits(&bytes, 23, DILITHIUM_N);
        assert_eq!(coeffs, back);
    }

    #[test]
    fn boundary_values_survive_masking() {
        // 0x0FFF (12-bit max) and Q must both be representable in the stream.
        let coeffs = vec![0x0FFF, KYBER_Q, 0, KYBER_Q - 1];
        let bytes = pack_bits(&coeffs, 12);
        let back = unpack_bits(&bytes, 12, coeffs.len());
        assert_eq!(back[0], 0x0FFF);
        assert_eq!(back[1], KYBER_Q & 0x0FFF); // 3329 fits in 12 bits
        assert_eq!(back[1], 3329);
    }

    #[test]
    fn compress_decompress_are_close() {
        // Round-trip error is bounded by ~q/2^(d+1) as a *modular* distance
        // (Compress rounds values near q up to ≡ 0).
        let bound = (KYBER_Q as i64) / (1 << 11) + 2;
        for &x in &[0u32, 100, 1664, 3000, 3328] {
            let c = compress(x, 10, KYBER_Q);
            let d = decompress(c, 10, KYBER_Q);
            let raw = (x as i64 - d as i64).abs();
            let err = raw.min(KYBER_Q as i64 - raw); // modular distance
            assert!(err <= bound, "x={x} d={d} err={err} bound={bound}");
        }
    }
}
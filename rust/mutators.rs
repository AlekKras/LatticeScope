//! Structure-aware mutation strategies.
//!
//! A blind byte fuzzer wastes almost all of its budget on inputs a packer
//! rejects. These strategies emit *structurally valid* coefficient vectors and
//! push them where lattice code actually breaks: reduction boundaries around
//! `q`, NTT-domain malformation, and signed wrap-around. The baseline strategy
//! stays strictly in-field, so any crash is attributable to a specific mutation
//! rather than to random garbage.

/// Deterministic SplitMix64. Tiny, dependency-free, and — crucially for a
/// fuzzer — fully reproducible from a single `u64` seed.
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng { state: seed }
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, n)`; returns 0 if `n == 0`.
    #[inline]
    pub fn below(&mut self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as u32
        }
    }

    #[inline]
    pub fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

fn field_max(bits: u32) -> u32 {
    if bits >= 32 {
        u32::MAX
    } else {
        (1u32 << bits) - 1
    }
}

/// The values a reduction/deserialisation bug is most likely to fire on. All
/// are clamped to what `bits` can represent, so packing reproduces them exactly.
pub fn boundary_values(q: u32, bits: u32) -> Vec<u32> {
    let fmax = field_max(bits);
    let mut v = vec![
        0,
        1,
        q.wrapping_sub(1),
        q,
        q.wrapping_add(1),
        fmax,             // all-ones: also "-1" read as signed
        1u32 << (bits - 1), // sign bit
    ];
    v.retain(|&x| x <= fmax);
    v.sort_unstable();
    v.dedup();
    v
}

pub trait Strategy {
    fn name(&self) -> &'static str;
    /// Produce `n` coefficients. `q` is the modulus, `bits` the packed width.
    fn generate(&self, rng: &mut Rng, n: usize, q: u32, bits: u32) -> Vec<u32>;
}

/// In-field uniform noise. Never emits a boundary value (we draw strictly below
/// `q`, and `field_max >= q` for every profile), so this is a clean baseline.
pub struct RandomValid;
impl Strategy for RandomValid {
    fn name(&self) -> &'static str {
        "random in-field baseline"
    }
    fn generate(&self, rng: &mut Rng, n: usize, q: u32, _bits: u32) -> Vec<u32> {
        (0..n).map(|_| rng.below(q)).collect()
    }
}

/// In-field baseline with a scatter of Montgomery/Barrett boundary values
/// (`q-1`, `q`, `q+1`, ...): stresses the reduction step.
pub struct MontgomeryBarrettBoundary;
impl Strategy for MontgomeryBarrettBoundary {
    fn name(&self) -> &'static str {
        "Montgomery/Barrett boundary stress"
    }
    fn generate(&self, rng: &mut Rng, n: usize, q: u32, bits: u32) -> Vec<u32> {
        let bv = boundary_values(q, bits);
        let mut out: Vec<u32> = (0..n).map(|_| rng.below(q)).collect();
        let hits = 1 + rng.below((n / 4).max(1) as u32) as usize;
        for _ in 0..hits {
            let idx = rng.below(n as u32) as usize;
            out[idx] = bv[rng.below(bv.len() as u32) as usize];
        }
        out
    }
}

/// Malformed NTT-domain layout: alternating extremes and clusters of `q-1`/`0`
/// that violate the coefficient-range assumption an inverse-NTT may rely on.
pub struct NttDomainMalform;
impl Strategy for NttDomainMalform {
    fn name(&self) -> &'static str {
        "NTT domain malformation"
    }
    fn generate(&self, rng: &mut Rng, n: usize, q: u32, bits: u32) -> Vec<u32> {
        let fmax = field_max(bits);
        let mut out = vec![0u32; n];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = if i % 2 == 0 { fmax } else { q.wrapping_sub(1) };
        }
        // perturb a few positions to keep coverage moving
        let jitter = 1 + rng.below((n / 8).max(1) as u32) as usize;
        for _ in 0..jitter {
            let idx = rng.below(n as u32) as usize;
            out[idx] = rng.below(q);
        }
        out
    }
}

/// Values chosen to wrap when re-interpreted as signed 16/32-bit integers
/// (sign bit set, all-ones = -1). `field_max` (e.g. 0x0FFF) lands here.
pub struct SignedWraparound;
impl Strategy for SignedWraparound {
    fn name(&self) -> &'static str {
        "signed wrap-around"
    }
    fn generate(&self, rng: &mut Rng, n: usize, q: u32, bits: u32) -> Vec<u32> {
        let fmax = field_max(bits);
        let sign = 1u32 << (bits - 1);
        let picks = [fmax, sign, sign.wrapping_add(1), fmax.wrapping_sub(1)];
        let mut out: Vec<u32> = (0..n).map(|_| rng.below(q)).collect();
        let hits = 1 + rng.below((n / 3).max(1) as u32) as usize;
        for _ in 0..hits {
            let idx = rng.below(n as u32) as usize;
            out[idx] = picks[rng.below(picks.len() as u32) as usize];
        }
        out
    }
}

/// The most surgical strategy: an all-in-field vector with exactly one
/// coefficient set to a single boundary value, cycling through the set. This is
/// what makes a crash trivially attributable to one coefficient.
pub struct SingleBoundaryInjection;
impl Strategy for SingleBoundaryInjection {
    fn name(&self) -> &'static str {
        "single boundary injection"
    }
    fn generate(&self, rng: &mut Rng, n: usize, q: u32, bits: u32) -> Vec<u32> {
        let bv = boundary_values(q, bits);
        let mut out: Vec<u32> = (0..n).map(|_| rng.below(q)).collect();
        let idx = rng.below(n as u32) as usize;
        out[idx] = bv[rng.below(bv.len() as u32) as usize];
        out
    }
}

pub fn default_strategies(family: crate::profiles::Family) -> Vec<Box<dyn Strategy>> {
    let mut v: Vec<Box<dyn Strategy>> = vec![
        Box::new(RandomValid),
        Box::new(MontgomeryBarrettBoundary),
        Box::new(NttDomainMalform),
        Box::new(SignedWraparound),
        Box::new(SingleBoundaryInjection),
    ];
    // Signature schemes lean harder on the surgical injector for t0/t1 unpacking.
    if family == crate::profiles::Family::Sign {
        v.push(Box::new(SingleBoundaryInjection));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packing::{KYBER_Q, unpack_bits, pack_bits};

    #[test]
    fn baseline_never_emits_triggers() {
        let s = RandomValid;
        let mut rng = Rng::new(12345);
        for _ in 0..500 {
            let c = s.generate(&mut rng, 256, KYBER_Q, 12);
            assert_eq!(c.len(), 256);
            assert!(c.iter().all(|&x| x < KYBER_Q)); // never 3329 or 4095
        }
    }

    #[test]
    fn boundary_set_contains_both_mock_triggers() {
        let bv = boundary_values(KYBER_Q, 12);
        assert!(bv.contains(&4095)); // -> NULL deref in mock
        assert!(bv.contains(&3329)); // -> div-by-zero in mock
    }

    #[test]
    fn strategies_stay_representable_after_packing() {
        let mut rng = Rng::new(7);
        for s in default_strategies(crate::profiles::Family::Kem) {
            let c = s.generate(&mut rng, 256, KYBER_Q, 12);
            let back = unpack_bits(&pack_bits(&c, 12), 12, 256);
            assert_eq!(c, back, "strategy {} not byte-stable", s.name());
        }
    }

    #[test]
    fn rng_is_deterministic() {
        let mut a = Rng::new(0xDEADBEEF);
        let mut b = Rng::new(0xDEADBEEF);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}
//! Parameter sets for ML-KEM (FIPS 203) and ML-DSA (FIPS 204), plus the
//! bundled mock.
//!
//! Sizes are the **final FIPS 204** values, not the pre-standardisation
//! round-3 CRYSTALS-Dilithium numbers (e.g. ML-DSA-44 sk = 2560, not 2528;
//! ML-DSA-87 sk = 4896, not 4864). Symbol names follow the PQClean / liboqs
//! `crypto_*` convention.

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Kem,
    Sign,
}

#[derive(Clone)]
pub struct Profile {
    pub name: &'static str,
    pub family: Family,
    pub n: usize,
    pub q: u32,
    /// Bit-width of a raw packed coefficient (Kyber poly = 12; Dilithium uses
    /// the full modulus width for the generic packer, = 23).
    pub poly_bits: u32,
    pub pk_len: usize,
    pub sk_len: usize,
    pub ct_len: usize,
    pub ss_len: usize,
    pub sig_len: usize,
    /// Compressed-ciphertext widths (FIPS 203 Table 2): bits/coefficient for
    /// the `u`/`v` parts respectively. 0 for signature profiles (no KEM
    /// ciphertext to compress).
    pub du: u32,
    pub dv: u32,
    pub sym_dec: &'static str,
    pub sym_enc: &'static str,
    pub sym_verify: &'static str,
}

pub const PROFILES: &[Profile] = &[
    Profile {
        name: "kyber512",
        family: Family::Kem,
        n: 256,
        q: 3329,
        poly_bits: 12,
        pk_len: 800,
        sk_len: 1632,
        ct_len: 768,
        ss_len: 32,
        sig_len: 0,
        du: 10,
        dv: 4,
        sym_dec: "crypto_kem_dec",
        sym_enc: "crypto_kem_enc",
        sym_verify: "",
    },
    Profile {
        name: "kyber768",
        family: Family::Kem,
        n: 256,
        q: 3329,
        poly_bits: 12,
        pk_len: 1184,
        sk_len: 2400,
        ct_len: 1088,
        ss_len: 32,
        sig_len: 0,
        du: 10,
        dv: 4,
        sym_dec: "crypto_kem_dec",
        sym_enc: "crypto_kem_enc",
        sym_verify: "",
    },
    Profile {
        name: "kyber1024",
        family: Family::Kem,
        n: 256,
        q: 3329,
        poly_bits: 12,
        pk_len: 1568,
        sk_len: 3168,
        ct_len: 1568,
        ss_len: 32,
        sig_len: 0,
        du: 11,
        dv: 5,
        sym_dec: "crypto_kem_dec",
        sym_enc: "crypto_kem_enc",
        sym_verify: "",
    },
    Profile {
        name: "dilithium2",
        family: Family::Sign,
        n: 256,
        q: 8_380_417,
        poly_bits: 23,
        pk_len: 1312,
        sk_len: 2560,
        ct_len: 0,
        ss_len: 0,
        sig_len: 2420,
        du: 0,
        dv: 0,
        sym_dec: "",
        sym_enc: "",
        sym_verify: "crypto_sign_verify",
    },
    Profile {
        name: "dilithium3",
        family: Family::Sign,
        n: 256,
        q: 8_380_417,
        poly_bits: 23,
        pk_len: 1952,
        sk_len: 4032,
        ct_len: 0,
        ss_len: 0,
        sig_len: 3309,
        du: 0,
        dv: 0,
        sym_dec: "",
        sym_enc: "",
        sym_verify: "crypto_sign_verify",
    },
    Profile {
        name: "dilithium5",
        family: Family::Sign,
        n: 256,
        q: 8_380_417,
        poly_bits: 23,
        pk_len: 2592,
        sk_len: 4896,
        ct_len: 0,
        ss_len: 0,
        sig_len: 4627,
        du: 0,
        dv: 0,
        sym_dec: "",
        sym_enc: "",
        sym_verify: "crypto_sign_verify",
    },
    Profile {
        name: "mock",
        family: Family::Kem,
        n: 256,
        q: 3329,
        poly_bits: 12,
        pk_len: 1184,
        sk_len: 2400,
        ct_len: 1088,
        ss_len: 32,
        sig_len: 0,
        du: 10,
        dv: 4,
        sym_dec: "crypto_kem_dec",
        sym_enc: "crypto_kem_enc",
        sym_verify: "",
    },
];

pub fn get(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.name == name)
}

pub fn names() -> Vec<&'static str> {
    PROFILES.iter().map(|p| p.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 203 ciphertext layout: ct = Compress(u, du) || Compress(v, dv),
    /// u has k polynomials, v has 1 -- so du*k*n/8 + dv*n/8 must equal ct_len
    /// for every KEM profile, with k solved back out of that same equation.
    #[test]
    fn du_dv_reconstruct_ct_len() {
        for p in PROFILES {
            if p.family != Family::Kem {
                assert_eq!((p.du, p.dv), (0, 0), "{}: signature profile must have du=dv=0", p.name);
                continue;
            }
            let c2_bytes = p.dv as usize * p.n / 8;
            let c1_total = p.ct_len - c2_bytes;
            let c1_per_poly = p.du as usize * p.n / 8;
            assert_eq!(c1_total % c1_per_poly, 0, "{}: du doesn't evenly divide ct_len", p.name);
            let k = c1_total / c1_per_poly;
            assert_eq!(
                p.du as usize * k * p.n / 8 + p.dv as usize * p.n / 8,
                p.ct_len,
                "{}: du/dv don't reconstruct ct_len",
                p.name
            );
        }
    }
}
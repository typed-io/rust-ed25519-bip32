#[derive(Debug, PartialEq, Eq)]
pub enum DerivationType {
    Soft(u32),
    Hard(u32),
}

/// Derivation index is a 32 bits number representing
/// a type of derivation and a 31 bits number.
///
/// The highest bit set represent a hard derivation,
/// whereas the bit clear represent soft derivation.
pub type DerivationIndex = u32;

impl DerivationType {
    pub fn from_index(index: DerivationIndex) -> Self {
        if index >= 0x80000000 {
            DerivationType::Hard(index)
        } else {
            DerivationType::Soft(index)
        }
    }
}

/// Ed25519-bip32 Scheme Derivation version
///
/// V1 should *not* be used in new code, it's only
/// still present for compability purpose with
/// deploy code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationScheme {
    V1,
    V2,
}

impl Default for DerivationScheme {
    fn default() -> Self {
        DerivationScheme::V2
    }
}

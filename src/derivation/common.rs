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
/// Only V2 is supported anymore, and this is
/// left as an API compatibility type. V1 has
/// been removed due to some shortcomings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationScheme {
    V2,
}

impl Default for DerivationScheme {
    fn default() -> Self {
        DerivationScheme::V2
    }
}

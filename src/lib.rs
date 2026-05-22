//! Ed25519 key handling using BIP32 style derivation
//!
//! Ed25519 is notable for its public key generation involving hashing and bit manipulations,
//! which seemingly prevents its use for BIP32. Instead this package use the ed25519 is
//! extended form (post-hashing).
//!
//! BIP32 allows derivation given a private key, of up to 2^32 children, using
//! two different derivation scheme (soft or hard).
//!
//! In soft derivation, the important property is that given the parent public key,
//! one can derive all softly derived children public key.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(error_in_core))]

#![cfg_attr(feature = "with-bench", feature(test))]
#[cfg(test)]
#[cfg(feature = "with-bench")]
extern crate test;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
extern crate core;

mod derivation;
mod hex;
mod key;
mod securemem;
mod signature;

#[cfg(test)]
mod tests;

#[cfg(test)]
#[cfg(feature = "with-bench")]
mod bench;

pub use derivation::{DerivationError, DerivationIndex, DerivationScheme};
pub use key::{PrivateKeyError, PublicKeyError, XPrv, XPub, XPRV_SIZE, XPUB_SIZE};
pub use signature::{Signature, SignatureError, SIGNATURE_SIZE};

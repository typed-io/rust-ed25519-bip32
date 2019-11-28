use std::fmt;

use cryptoxide::digest::Digest;
use cryptoxide::ed25519;
use cryptoxide::ed25519::signature_extended;
use cryptoxide::sha2::Sha512;
use cryptoxide::util::fixed_time_eq;

use std::error::Error;
use std::hash::{Hash, Hasher};

use super::derivation::{self, DerivationError, DerivationIndex, DerivationScheme};
use super::hex;
use super::securemem;
use super::signature::Signature;

/// Extended Private key size in bytes
pub const XPRV_SIZE: usize = 96;

/// Extended Public key size in bytes
pub const XPUB_SIZE: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const CHAIN_CODE_SIZE: usize = 32;

/// Possible errors during conversion from bytes
///
/// HighestBitsInvalid and LowestBitsInvalid are errors
/// reported linked to the shape of a normal extended ed25519 key.
///
#[derive(Debug, PartialEq, Eq)]
pub enum PrivateKeyError {
    LengthInvalid(usize),
    HighestBitsInvalid,
    LowestBitsInvalid,
}

/// Possible errors during conversion from bytes
#[derive(Debug)]
pub enum PublicKeyError {
    LengthInvalid(usize),
}

/// HDWallet extended private key
///
/// Effectively this is an ed25519 extended secret key (64 bytes) followed by a chain code (32 bytes).
///
pub struct XPrv([u8; XPRV_SIZE]);
impl XPrv {
    /// takes the given raw bytes and perform some modifications to normalize
    /// to a valid Ed25519 extended key, but it does also force
    /// the 3rd highest bit to be cleared too.
    pub fn normalize_bytes_force3rd(mut bytes: [u8; XPRV_SIZE]) -> Self {
        bytes[0] &= 0b1111_1000;
        bytes[31] &= 0b0001_1111;
        bytes[31] |= 0b0100_0000;

        Self::from_bytes(bytes)
    }

    /// Takes the given raw bytes and perform some modifications to normalize
    /// to a valid Ed25519 extended key. It doesn't touch the 3rd highest bit
    /// as expected in the ed25519-bip32 paper.
    pub fn normalize_bytes_ed25519(mut bytes: [u8; XPRV_SIZE]) -> Self {
        bytes[0] &= 0b1111_1000;
        bytes[31] &= 0b0011_1111;
        bytes[31] |= 0b0100_0000;

        Self::from_bytes(bytes)
    }

    /// Check if the 3rd highest bit is clear as expected from the paper
    pub fn is_3rd_highest_bit_clear(&self) -> bool {
        (self.0[31] & 0b0010_0000) == 0
    }

    /// Clear the 3rd highest bit as expected from the paper setting
    pub fn clear_3rd_highest_bit(mut self) -> Self {
        self.0[31] &= 0b1101_1111;
        self
    }

    /// Takes a non-extended Ed25519 secret key and hash through SHA512 it in the same way the standard
    /// Ed25519 signature system make extended key, but *also* force clear the 3rd highest bit of the key
    /// instead of returning an error
    pub fn from_nonextended_force(bytes: &[u8; 32], chain_code: &[u8; CHAIN_CODE_SIZE]) -> Self {
        let mut extended_out = [0u8; XPRV_SIZE];
        let mut hasher = Sha512::new();
        hasher.input(bytes);
        hasher.result(&mut extended_out[0..64]);
        extended_out[64..96].clone_from_slice(chain_code);
        Self::normalize_bytes_force3rd(extended_out)
    }

    /// Takes a non-extended Ed25519 secret key and hash through SHA512 it in the same way the standard
    /// Ed25519 signature system make extended key. If the 3rd highest bit is set, then return an error
    ///
    /// bip32-ed25519 paper:
    ///
    /// > "2) We admit only those ~k such that the third highest bit of the last byte of kL is zero."
    pub fn from_nonextended_noforce(
        bytes: &[u8; 32],
        chain_code: &[u8; CHAIN_CODE_SIZE],
    ) -> Result<Self, ()> {
        let mut extended_out = [0u8; XPRV_SIZE];
        let mut hasher = Sha512::new();
        hasher.input(bytes);
        hasher.result(&mut extended_out[0..64]);
        extended_out[64..96].clone_from_slice(chain_code);
        let xprv = Self::normalize_bytes_ed25519(extended_out);
        if xprv.is_3rd_highest_bit_clear() {
            Ok(xprv)
        } else {
            Err(())
        }
    }

    // Create a XPrv from the given bytes.
    //
    // This function does not perform any validity check and should not be used outside
    // of this crate.
    pub(crate) fn from_bytes(bytes: [u8; XPRV_SIZE]) -> Self {
        XPrv(bytes)
    }

    /// Create a `XPrv` by taking ownership of the given array
    ///
    /// This function may returns an error if it does not have the expected
    /// format.
    ///
    /// This function allow the 3rd highest bit to not be clear (to handle potential derived valid xprv),
    /// but self.is_3rd_highest_bit_clear() can be called to check if the 3rd highest bit
    /// is assumed to be clear or not.
    pub fn from_bytes_verified(bytes: [u8; XPRV_SIZE]) -> Result<Self, PrivateKeyError> {
        let scalar = &bytes[0..32];
        let last = scalar[31];
        let first = scalar[0];

        if (last & 0b1100_0000) != 0b0100_0000 {
            return Err(PrivateKeyError::HighestBitsInvalid);
        }
        if (first & 0b0000_0111) != 0b0000_0000 {
            return Err(PrivateKeyError::LowestBitsInvalid);
        }

        Ok(XPrv(bytes))
    }

    pub fn from_slice_verified(bytes: &[u8]) -> Result<Self, PrivateKeyError> {
        if bytes.len() != XPRV_SIZE {
            return Err(PrivateKeyError::LengthInvalid(bytes.len()));
        }

        let mut buf = [0u8; XPRV_SIZE];
        buf[..].clone_from_slice(bytes);
        XPrv::from_bytes_verified(buf)
    }

    /// Create a `XPrv` from the given slice. This slice must be of size `XPRV_SIZE`
    /// otherwise it will return `Err`.
    ///
    fn from_slice(bytes: &[u8]) -> Result<Self, PrivateKeyError> {
        if bytes.len() != XPRV_SIZE {
            return Err(PrivateKeyError::LengthInvalid(bytes.len()));
        }
        let mut buf = [0u8; XPRV_SIZE];
        buf[..].clone_from_slice(bytes);
        Ok(XPrv::from_bytes(buf))
    }

    /// Get the associated `XPub`
    ///
    pub fn public(&self) -> XPub {
        let pk = mk_public_key(&self.as_ref()[0..64]);
        let mut out = [0u8; XPUB_SIZE];
        out[0..32].clone_from_slice(&pk);
        out[32..64].clone_from_slice(&self.as_ref()[64..]);
        XPub::from_bytes(out)
    }

    /// sign the given message with the `XPrv`.
    ///
    pub fn sign<T>(&self, message: &[u8]) -> Signature<T> {
        Signature::from_bytes(signature_extended(message, &self.as_ref()[0..64]))
    }

    /// verify a given signature
    ///
    pub fn verify<T>(&self, message: &[u8], signature: &Signature<T>) -> bool {
        let xpub = self.public();
        xpub.verify(message, signature)
    }

    pub fn derive(&self, scheme: DerivationScheme, index: DerivationIndex) -> Self {
        derivation::private(self, index, scheme)
    }

    pub fn get_extended(&self, out: &mut [u8; 64]) {
        out.clone_from_slice(&self.as_ref()[0..64])
    }
}
impl PartialEq for XPrv {
    fn eq(&self, rhs: &XPrv) -> bool {
        fixed_time_eq(self.as_ref(), rhs.as_ref())
    }
}
impl Eq for XPrv {}
impl Clone for XPrv {
    fn clone(&self) -> Self {
        Self::from_slice(self.as_ref()).expect("it is already a safely constructed XPrv")
    }
}
impl fmt::Debug for XPrv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}
impl fmt::Display for XPrv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}
impl AsRef<[u8]> for XPrv {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl From<XPrv> for [u8; XPRV_SIZE] {
    fn from(v: XPrv) -> [u8; XPRV_SIZE] {
        v.0
    }
}
impl Drop for XPrv {
    fn drop(&mut self) {
        securemem::zero(&mut self.0);
    }
}

/// Extended Public Key (Point + ChainCode)
#[derive(Clone, Copy)]
pub struct XPub([u8; XPUB_SIZE]);
impl XPub {
    /// create a `XPub` by taking ownership of the given array
    pub fn from_bytes(bytes: [u8; XPUB_SIZE]) -> Self {
        XPub(bytes)
    }

    /// create a `XPub` from the given slice. This slice must be of size `XPUB_SIZE`
    /// otherwise it will return `Option::None`.
    ///
    pub fn from_slice(bytes: &[u8]) -> Result<Self, PublicKeyError> {
        if bytes.len() != XPUB_SIZE {
            return Err(PublicKeyError::LengthInvalid(bytes.len()));
        }
        let mut buf = [0u8; XPUB_SIZE];
        buf[..].clone_from_slice(bytes);
        Ok(Self::from_bytes(buf))
    }

    /// verify a signature
    ///
    pub fn verify<T>(&self, message: &[u8], signature: &Signature<T>) -> bool {
        ed25519::verify(message, &self.as_ref()[0..32], signature.as_ref())
    }

    pub fn derive(
        &self,
        scheme: DerivationScheme,
        index: DerivationIndex,
    ) -> Result<Self, DerivationError> {
        derivation::public(self, index, scheme)
    }

    pub fn get_without_chaincode(&self, out: &mut [u8; 32]) {
        out.clone_from_slice(&self.0[0..32])
    }
}
impl PartialEq for XPub {
    fn eq(&self, rhs: &XPub) -> bool {
        fixed_time_eq(self.as_ref(), rhs.as_ref())
    }
}
impl Eq for XPub {}
impl Hash for XPub {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.0)
    }
}
impl fmt::Display for XPub {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}
impl fmt::Debug for XPub {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}
impl AsRef<[u8]> for XPub {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl From<XPub> for [u8; XPUB_SIZE] {
    fn from(v: XPub) -> [u8; XPUB_SIZE] {
        v.0
    }
}

impl fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PublicKeyError::LengthInvalid(length) => write!(
                f,
                "Invalid public key length, expected {} but received {}",
                XPUB_SIZE, length
            ),
        }
    }
}
impl Error for PublicKeyError {}

impl fmt::Display for PrivateKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrivateKeyError::LengthInvalid(length) => write!(
                f,
                "Invalid private key length, expected {} but received {}",
                XPRV_SIZE, length
            ),
            PrivateKeyError::HighestBitsInvalid => f.write_str("Invalid highest bits"),
            PrivateKeyError::LowestBitsInvalid => f.write_str("Invalid lowest bits"),
        }
    }
}
impl Error for PrivateKeyError {}

pub(crate) fn mk_xprv(out: &mut [u8; XPRV_SIZE], kl: &[u8], kr: &[u8], cc: &[u8]) {
    assert!(kl.len() == 32);
    assert!(kr.len() == 32);
    assert!(cc.len() == CHAIN_CODE_SIZE);

    out[0..32].clone_from_slice(kl);
    out[32..64].clone_from_slice(kr);
    out[64..96].clone_from_slice(cc);
}

pub(crate) fn mk_xpub(out: &mut [u8; XPUB_SIZE], pk: &[u8], cc: &[u8]) {
    assert!(pk.len() == 32);
    assert!(cc.len() == CHAIN_CODE_SIZE);

    out[0..32].clone_from_slice(pk);
    out[32..64].clone_from_slice(cc);
}

pub fn mk_public_key(extended_secret: &[u8]) -> [u8; PUBLIC_KEY_SIZE] {
    assert!(extended_secret.len() == 64);
    ed25519::to_public(extended_secret)
}

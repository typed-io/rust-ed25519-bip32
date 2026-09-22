mod common;
pub mod v2;

use core::{
    convert::{TryFrom, TryInto},
    error::Error,
    fmt,
};
use cryptoxide::curve25519::{Ge, Scalar};
use cryptoxide::hashing::sha2::Sha512;
use cryptoxide::hmac;

use super::key::{XPRV_SIZE, XPUB_SIZE, XPrv, XPub, mk_public_key, mk_xprv, mk_xpub};
pub use common::{DerivationIndex, DerivationScheme, DerivationType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationError {
    InvalidAddition,
    ExpectedSoftDerivation,
}

fn add_256bits(x: &[u8; 32], y: &[u8; 32], scheme: DerivationScheme) -> [u8; 32] {
    match scheme {
        DerivationScheme::V2 => v2::add_256bits_v2(x, y),
    }
}

fn add_28_mul8(x: &[u8; 32], y: &[u8; 32], scheme: DerivationScheme) -> [u8; 32] {
    match scheme {
        DerivationScheme::V2 => v2::add_28_mul8_v2(x, y),
    }
}

fn serialize_index(i: u32, derivation_scheme: DerivationScheme) -> [u8; 4] {
    match derivation_scheme {
        DerivationScheme::V2 => v2::le32(i),
    }
}

pub fn private(xprv: &XPrv, index: DerivationIndex, scheme: DerivationScheme) -> XPrv {
    /*
     * If so (hardened child):
     *    let Z = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(left(kpar)) || ser32(i)).
     *    let I = HMAC-SHA512(Key = cpar, Data = 0x01 || ser256(left(kpar)) || ser32(i)).
     * If not (normal child):
     *    let Z = HMAC-SHA512(Key = cpar, Data = 0x02 || serP(point(kpar)) || ser32(i)).
     *    let I = HMAC-SHA512(Key = cpar, Data = 0x03 || serP(point(kpar)) || ser32(i)).
     **/

    let ekey = xprv.extended_secret_key_bytes();
    let kl: &[u8; 32] = &ekey[0..32].try_into().unwrap();
    let kr: &[u8; 32] = &ekey[32..64].try_into().unwrap();
    let chaincode = &xprv.as_ref()[64..96];

    let mut zmac = hmac::Context::<Sha512>::new(&chaincode);
    let mut imac = hmac::Context::<Sha512>::new(&chaincode);
    let seri = serialize_index(index, scheme);
    match DerivationType::from_index(index) {
        DerivationType::Soft(_) => {
            let pk = mk_public_key(ekey);
            zmac.update(&[0x2]);
            zmac.update(&pk);
            zmac.update(&seri);
            imac.update(&[0x3]);
            imac.update(&pk);
            imac.update(&seri);
        }
        DerivationType::Hard(_) => {
            zmac.update(&[0x0]);
            zmac.update(ekey);
            zmac.update(&seri);
            imac.update(&[0x1]);
            imac.update(ekey);
            imac.update(&seri);
        }
    };

    let zout = zmac.finalize();
    let zl: &[u8; 32] = &zout.as_ref()[0..32].try_into().unwrap();
    let zr: &[u8; 32] = &zout.as_ref()[32..64].try_into().unwrap();

    // left = kl + 8 * trunc28(zl)
    let left = add_28_mul8(kl, zl, scheme);
    // right = zr + kr
    let right = add_256bits(kr, zr, scheme);

    // note: we don't perform the check for curve order divisibility because it will not happen:
    // 1. all keys are in the range K=2^254 .. 2^255 (actually the even smaller range 2^254+2^253)
    // 2. all keys are also multiple of 8
    // 3. all existing multiple of the curve order n in the range of K are not multiple of 8

    let iout = imac.finalize();
    let cc = &iout.as_ref()[32..];

    let mut out = [0u8; XPRV_SIZE];
    mk_xprv(&mut out, &left, &right, cc);

    XPrv::from_bytes(out)
}

fn point_of_trunc28_mul8(sk: &[u8; 32], scheme: DerivationScheme) -> [u8; 32] {
    let copy = add_28_mul8(&[0u8; 32], sk, scheme);
    let scalar = Scalar::from_bytes(&copy);
    let a = Ge::scalarmult_base(&scalar);
    a.to_bytes()
}

fn point_plus(p1: &[u8; 32], p2: &[u8; 32]) -> Result<[u8; 32], DerivationError> {
    let a = match Ge::from_bytes(p1) {
        Some(g) => g,
        None => {
            return Err(DerivationError::InvalidAddition);
        }
    };
    let b = match Ge::from_bytes(p2) {
        Some(g) => g,
        None => {
            return Err(DerivationError::InvalidAddition);
        }
    };
    let r = &a + &b.to_cached();
    let mut r = r.to_full().to_bytes();
    r[31] ^= 0x80;
    Ok(r)
}

pub fn public(
    xpub: &XPub,
    index: DerivationIndex,
    scheme: DerivationScheme,
) -> Result<XPub, DerivationError> {
    let pk = <&[u8; 32]>::try_from(&xpub.as_ref()[0..32]).unwrap();
    let chaincode = &xpub.as_ref()[32..64];

    let mut zmac = hmac::Context::<Sha512>::new(&chaincode);
    let mut imac = hmac::Context::<Sha512>::new(&chaincode);
    let seri = serialize_index(index, scheme);
    match DerivationType::from_index(index) {
        DerivationType::Soft(_) => {
            zmac.update(&[0x2]);
            zmac.update(pk);
            zmac.update(&seri);
            imac.update(&[0x3]);
            imac.update(pk);
            imac.update(&seri);
        }
        DerivationType::Hard(_) => {
            return Err(DerivationError::ExpectedSoftDerivation);
        }
    };

    let zout = zmac.finalize();
    let zl = <&[u8; 32]>::try_from(&zout.as_ref()[0..32]).unwrap();
    let _zr = &zout.as_ref()[32..64];

    // left = kl + 8 * trunc28(zl)
    let left = point_plus(pk, &point_of_trunc28_mul8(zl, scheme))?;

    let iout = imac.finalize();
    let cc = &iout.as_ref()[32..];

    let mut out = [0u8; XPUB_SIZE];
    mk_xpub(&mut out, &left, cc);

    Ok(XPub::from_bytes(out))
}

impl fmt::Display for DerivationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DerivationError::InvalidAddition => f.write_str("Invalid addition"),
            DerivationError::ExpectedSoftDerivation => f.write_str("Expected a soft derivation"),
        }
    }
}
impl Error for DerivationError {}

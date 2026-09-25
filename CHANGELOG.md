# Changelog

## Unreleased

- Update CI to check the Rust 1.85 minimum supported version.

## 0.5.0 - 2026-09-22

- **Breaking:** Remove `Debug` and `Display` implementations for `XPrv` to
  prevent accidental disclosure of private keys through formatting.
- Move to Rust edition 2024 and raise the minimum supported Rust version to 1.85.
- Disable default features for `cryptoxide`, enabling only `ed25519`, `sha2`,
  and `hmac`.
- Harden private-key memory wiping with volatile writes, compiler fences, and
  optimization barriers.

## 0.4.3 - 2026-07-29

- Make the crate unconditionally `no_std`, without requiring `alloc` or a
  feature flag.
- Declare Rust 1.81 as the minimum supported version and move to Rust edition 2021.
- Update `cryptoxide` to 0.6.
- Add CI checks for the minimum supported Rust version and an embedded target.

## 0.4.2 - 2026-05-22

- Update `cryptoxide` to 0.5.
- Add the Apache 2.0 license file alongside the MIT license to match the
  existing dual-license metadata, and update license notices.
- Add CI and expand the README with features and alternative implementations.

## 0.4.1 - 2022-01-28

- Update `cryptoxide` to 0.4.

## 0.4.0 - 2021-06-22

- **Breaking:** Remove V1 derivation support. V2 remains supported; applications
  needing V1 compatibility must use the 0.3 series to migrate existing keys.
- Add a README documenting the removal of V1 derivation.

## 0.3.2 - 2021-01-27

- Update `cryptoxide` to 0.3.
- Fix benchmarks that still used the removed `normalize_bytes` method.

## 0.3.1 - 2020-03-20

- Update `cryptoxide` to 0.2.

## 0.3.0 - 2019-12-02

- Add the `EXTENDED_SECRET_KEY_SIZE` constant.
- Add constructors for extended private and public keys from their components.
- Add slice and component accessors for extended private and public keys.

## 0.2.0 - 2019-11-28

- **Breaking:** Replace `XPrv::normalize_bytes` with
  `normalize_bytes_ed25519` and `normalize_bytes_force3rd` for explicit control
  over the third-highest scalar bit.
- **Breaking:** Replace `XPrv::from_nonextended` with
  `from_nonextended_force` and `from_nonextended_noforce`.
- Add methods to inspect and clear the third-highest scalar bit.
- Allow `XPrv::from_bytes_verified` to accept derived keys with that bit set.

## 0.1.5 - 2019-11-05

- Implement standard error traits for private-key, public-key, derivation,
  and signature errors.

## 0.1.4 - 2019-09-27

- **Breaking:** Add a chain-code argument to `XPrv::from_nonextended`.

## 0.1.3 - 2019-09-27

- Add construction of extended private keys from non-extended Ed25519 secret keys.

## 0.1.2 - 2019-09-26

- Export `DerivationError` from the crate root.

## 0.1.1 - 2019-06-10

- Add conversions from `XPrv` and `XPub` into their underlying byte arrays.

## 0.1.0 - 2019-06-04

- Initial implementation of Ed25519 BIP32 key derivation and signing.

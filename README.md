# implementation of bip32 for ed25519

Provide an implementation of BIP32 for the edwards 25519 curve, based on a
[BIP32-ed25519](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf)
paper from Dmitry Khovratovich and Jason Law.

# Features

* small dependency tree : only depends on 1 package [cryptoxide](https://github.com/typed-io/cryptoxide/) which has no other dependencies.
* compatible with [cardano](https://cardano.org) key derivation
* used by the [jormungandr](https://github.com/input-output-hk/jormungandr) node

## Derivation V1

the "V1" derivation has been removed from this package, as it has massive
shortcomings. If you need it for some compatibility reason, you can use version
0.3 of this package. It is important that it's only used to convert everything
to V2 or another scheme, as using V1 should be considered deprecated, dangerous
and might eat your dog.

## Alternative Derivation packages

not an exhaustive list, or endorsements, but some alternative approach to deriving with ED25519:

* [slip10\_ed25519](https://crates.io/crates/slip10_ed25519): using slip10
* [ed25519-dalek-bip32](https://github.com/jpopesculian/ed25519-dalek-bip32) : doesn't support bip32 soft derivation concept, but closer to the bip32 and ed25519 specs
* [hd-ed25519](https://github.com/w3f/hd-ed25519): using ristretto instead of doing careful arithmetic

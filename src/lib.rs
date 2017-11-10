//! the `eth-crypto` crate contains simple abstractions for
//! performing the common cryptography functionalities used
//! by the Ethereum blockchain.  this crate is intended for
//! educational purposes only, and comes with absolutely no
//! warranty or assurances of correctness.  the tools
//! exposed by this crate prioritize simplicity and ease of
//! use over speed or efficiency, and do not necessarily
//! represent best-practices for cryptography in general,
//! or ethereum-style cryptography in particular.
#![warn(missing_docs)]
extern crate tiny_keccak;
extern crate secp256k1;
extern crate rand;
extern crate hex;

#[macro_use]
extern crate lazy_static;

#[macro_use]
mod utils;

pub mod types;
pub mod hash;
pub mod ecc;


/// the `prelude` module re-exports commonly used 
/// functions & types for convenience of use.
pub mod prelude {
    pub use self::v1::*;

    /// version one of the `prelude` module.
    pub mod v1 {
        pub use types::Result;
        pub use hash::keccak256::{Hash,hash,hash_many};
        pub use ecc::{Signature,Address,Public,Private,keygen,recover,ecrecover};
    }

}

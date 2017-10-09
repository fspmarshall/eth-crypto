#![warn(missing_docs)]
extern crate tiny_keccak;
extern crate secp256k1;

#[macro_use]
extern crate lazy_static;
pub mod types;
pub mod hash;
pub mod ecc;

pub use hash::{hash,hash_many};


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

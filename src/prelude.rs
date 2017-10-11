//! the `prelude` module reexports the core functionality of the crate.
//! think of it like a quickstart for imports.


pub mod v1 {
    pub use types::Result;
    pub use hash::keccak256::{hash,hash_many};
    pub use ecc::{Signature,Address,Public,Private};
}



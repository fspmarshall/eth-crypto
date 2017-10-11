//! the `hash` submodule contains functions for hashing.  we're
//! really burying the lead on this one.


/// the `keccak-256` hashing function is the defacto hashing algorithm used
/// in the Ethereum Virtual Machine.  we may add additional hashing
/// algorithms later, so we keep these functions in their own submodule
/// in the interest of forwards-compatability. prelude `v1` exposes the 
/// `keccak-256` `hash` and `hash_many` function as the default hash 
/// implementations. 
pub mod keccak256 {
    use tiny_keccak::Keccak;

    /// generate the `keccak-256` hash of a piece of data.
    /// if you are trying to hash multiple discontiguous
    /// values together, use `hash_many` instead.
    pub fn hash<T>(data: T) -> [u8;32] where T: AsRef<[u8]> {
        let mut buffer = [0u8;32];
        Keccak::keccak256(data.as_ref(),&mut buffer);
        buffer
    }

    /// generate the `keccak-256` hash of a slice of multiple
    /// elements of any type which implements `AsRef<[u8]>`.
    /// byte-representations are tightly-packed, so any padding
    /// between elements must be added prior.
    /// if you are trying to hash a single contiguous value,
    /// use `hash` instead.
    pub fn hash_many<T>(data: &[T]) -> [u8;32] where T: AsRef<[u8]> {
        let mut keccak = Keccak::new_keccak256();
        let mut buffer = [0u8;32];
        for itm in data {
            keccak.update(itm.as_ref());
        }
        keccak.finalize(&mut buffer);
        buffer
    }

}

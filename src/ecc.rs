//! the `ecc` module contains all types and functions related to
//! performing elliptic curve cryptography on the `secp256k1`
//! curve.
use secp256k1::{Secp256k1,Message,RecoveryId,RecoverableSignature};
use secp256k1::key::{PublicKey,SecretKey};
use std::convert::From;
use rand::OsRng;
use hash::keccak256::hash;
use types::Result;


// -------------------------- misc -----------------------------


lazy_static! {
    static ref SECP256K1: Secp256k1 = Secp256k1::new();
}


// --------------------- ecc function defs ---------------------


/// generate a random public/private keypair.
pub fn keygen() -> Result<(Public,Private)> {
    let ctx = &SECP256K1;
    let mut rng = OsRng::new()?;
    let (_private,_public) = ctx.generate_keypair(&mut rng)?;
    Ok((Public::from(_public),Private::from(_private)))
}


/// recover the address assoicated with a message hash and signature.
#[inline]
pub fn ecrecover(msg: &[u8;32], sig: &Signature) -> Result<Address> {
    let public = recover(msg,sig)?;
    Ok(Address::from(public))
}


/// recover the public key associated with a message hash and signature.
#[inline]
pub fn recover(msg: &[u8;32], sig: &Signature) -> Result<Public> {
    let pk = _recover(msg,sig)?;
    Ok(Public::from(pk))
}


// low-level conversion function for deriving an `secp256k1::PublicKey` object
// from a given message/signature.
#[inline]
fn _recover(msg: &[u8;32], sig: &Signature) -> Result<PublicKey> {
    let ctx = &SECP256K1;
    let rid = RecoveryId::from_i32(sig[64] as i32)?;
    let rec = RecoverableSignature::from_compact(ctx, &sig[0..64], rid)?;
    let key = ctx.recover(&Message::from(*msg), &rec)?;
    Ok(key)
}


// --------------------- ecc type defs ---------------------

/// an ethereum-style address.
#[derive(Debug,Clone,Hash,PartialEq, Eq)]
pub struct Address([u8; 20]);

impl_byte_array!(Address,20);

impl From<Public> for Address {
    fn from(key: Public) -> Self {
        let hsh = hash(key.as_ref());
        let mut buf = [0u8;20];
        for (idx,val) in hsh[12..].into_iter().enumerate() {
            buf[idx] = *val;
        }
        Address(buf)
    }
}


/// an ethereum-style signature.
pub struct Signature([u8;65]);

impl_byte_array!(Signature,65);
impl_byte_array_ext!(Signature,65);

impl Signature {
    /// Split the signature into its `(v,r,s)` component
    /// representation.  *note*: signatures are actually ordered
    /// as `(r,s,v)` in their default byte-representation. The
    /// `ecrecover` function of the EVM takes its component arguments
    /// in the `(v,r,s)` ordering, so we follow that convention here.
    pub fn split(&self) -> (u8,&[u8],&[u8]) {
        (self.get_v(),self.get_r(),self.get_s())
    }
    /// extract the `v` component of the signature.
    pub fn get_v(&self) -> u8 { self.0[64] }
    /// extract the `r` component of the signature.
    pub fn get_r(&self) -> &[u8] { &self.0[0..32] }
    /// extract the `s` component of the signature.
    pub fn get_s(&self) -> &[u8] { &self.0[32..65] }
}


/// an ecc public-key on the `secp256k1` curve.
pub struct Public([u8;64]);

impl_byte_array!(Public,64);
impl_byte_array_ext!(Public,64);

impl From<PublicKey> for Public {
    // convert the specified `PublicKey` object into
    // an ethereum-style key representation.  primarily
    // used for deriving a corresponding `Address`.
    fn from(key: PublicKey) -> Self {
        let ctx = &SECP256K1;
        let ser = key.serialize_vec(ctx, false);
        let mut buf: [u8; 64] = [0; 64];
        for (idx,val) in ser[1..65].into_iter().enumerate() {
            buf[idx] = *val;
        }
        Public(buf)
    }
}


/// an ecc private-key on the `secp256k1` curve.
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Private([u8;32]);

impl_byte_array!(Private,32);

impl From<SecretKey> for Private {
    fn from(key: SecretKey) -> Self {
        let mut buf = [0u8;32];
        for (idx,val) in key[0..32].into_iter().enumerate() {
            buf[idx] = *val;
        }
        Private(buf)
    }
}

/// struct representing a public/private keypair on the
/// `secp256k1` curve.



#[cfg(test)]
mod tests {

    #[test]
    fn signing() {
    }

    #[test]
    fn addressing() {
    }

    #[test]
    fn conversion() {
    }
}



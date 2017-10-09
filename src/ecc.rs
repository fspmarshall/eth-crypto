use secp256k1::{Secp256k1,Message,RecoveryId,RecoverableSignature};
use secp256k1::key::{PublicKey,SecretKey};
use types::{Result,Signature,Address,Public,Private};
use rand::{Rng,OsRng};


lazy_static! {
    pub static ref SECP256K1: Secp256k1 = Secp256k1::new();
}


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


use secp256k1::{Secp256k1,Message,RecoveryId,RecoverableSignature};
use secp256k1::key::{PublicKey,SecretKey};
use types::{Result,Signature,Address};

lazy_static! {
    pub static ref SECP256K1: Secp256k1 = Secp256k1::new();
}


#[inline]
fn _recover(sig: &Signature, msg: &[u8;32]) -> Result<PublicKey> {
    let ctx = &SECP256K1;
    let rid = RecoveryId::from_i32(sig[64] as i32)?;
    let rec = RecoverableSignature::from_compact(ctx, &sig[0..64], rid)?;
    let key = ctx.recover(&Message::from(*msg), &rec)?;
    Ok(key)
}


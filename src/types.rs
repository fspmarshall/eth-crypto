use std::convert::From;
use std::ops::Deref;
use std::{io,result,error,fmt};
use secp256k1::key::{PublicKey,SecretKey};
use secp256k1;
use ecc::SECP256K1;
use hash::hash;


/// custom result alias.  this library is intended for
pub type Result<T> = result::Result<T,Error>;


/// an ethereum-style address.
#[derive(Hash, PartialEq, Eq)]
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



// --------------------- secp256k1 ecc-keys ---------------------

/// an ecc public-key on the `secp256k1` curve.
pub struct Public([u8;64]);

impl_byte_array!(Public,64);

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


// --------------------- error-handling ---------------------

/// custom error type for this library.
#[derive(Debug)]
pub enum Error {
    /// error raised during signature verification.
    SigErr(secp256k1::Error),
    /// error raised during normal io operations.
    IoErr(io::Error),
    /// generic error.
    Misc(&'static str)
}


// we need to explicitly implement `Display` to allow
// our errors to be properly printed by the `Error` trait.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::SigErr(ref err) => write!(f, "Signature error: {}", err),
            Error::IoErr(ref err) => write!(f, "Io Error: {}", err),
            Error::Misc(ref val) => write!(f, "Miscellaneous error: {}", val)
        }
    }
}


impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::SigErr(ref err) => err.description(),
            Error::IoErr(ref err) => err.description(),
            Error::Misc(ref val) => val
        }

    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::SigErr(ref err) => Some(err),
            Error::IoErr(ref err) => Some(err),
            Error::Misc(..) => None
        }
    }
}


// impl to allow implicit convertion from `secp256k1::Error`.
impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Self {
        Error::SigErr(err)
    }
}

// impl to allow implicit convertion from `std::io::Error`.
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IoErr(err)
    }
}

// impl to allow implicit converions from generic `&str` style arrors.
impl From<&'static str> for Error {
    fn from(err: &'static str) -> Self {
        Error::Misc(err)
    }
}

use std::convert::From;
use std::ops::Deref;
use std::{result,error,fmt};
use secp256k1;


/// custom result alias.  this library is intended for
pub type Result<T> = result::Result<T,Error>;



/// an ethereum-style address.
#[derive(Hash, PartialEq, Eq)]
pub struct Address([u8; 20]);

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl From<[u8; 20]> for Address {
    fn from(itm: [u8; 20]) -> Address { Address(itm) }
}

impl Deref for Address {
    type Target = [u8;20];
    fn deref(&self) -> &Self::Target { &self.0 }
}



/// an ethereum-style signature.
pub struct Signature([u8;65]);

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

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl From<[u8; 65]> for Signature {
    fn from(itm: [u8; 65]) -> Signature { Signature(itm) }
}

impl Deref for Signature {
    type Target = [u8;65];
    fn deref(&self) -> &Self::Target { &self.0 }
}


/// an ecc public-key on the `secp256k1` curve.
pub struct Public([u8;64]);


/// an ecc private-key on the `secp256k1` curve.
pub struct Private([u8;64]);


/// custom error type for this library.
#[derive(Debug, Copy, Clone)]
pub enum Error {
    /// error raised during signature verification.
    SigErr(secp256k1::Error),
    /// generic error.
    Misc(&'static str),
}


// we need to explicitly implement `Display` to allow
// our errors to be properly printed by the `Error` trait.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::SigErr(ref err) => write!(f, "Signature error: {}", err),
            Error::Misc(ref val) => write!(f, "Miscellaneous error: {}", val),
        }
    }
}


impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::SigErr(ref err) => err.description(),
            Error::Misc(ref val) => val,
        }

    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::SigErr(ref err) => Some(err),
            Error::Misc(..) => None,
        }
    }
}


// impl to allow implicit convertion from `secp256k1::Error`.
impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Error {
        Error::SigErr(err)
    }
}

// impl to allow implicit converions from generic `&str` style arrors.
impl From<&'static str> for Error {
    fn from(err: &'static str) -> Error {
        Error::Misc(err)
    }
}

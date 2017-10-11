//! the `types` module contains any type definitions which are
//! of general usefullness.
use std::{io,result,error,fmt};
use secp256k1::key::{PublicKey,SecretKey};
use secp256k1;
use ecc::SECP256K1;
use hash::keccak256::hash;


/// custom result alias.
pub type Result<T> = result::Result<T,Error>;


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

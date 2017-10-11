
/// Many of our types are "newtype" wrappers around byte-arrays.  This macro implements
/// a set of useful traits 
macro_rules! impl_byte_array {
    // take the name ($ident) and byte-length ($len) of target.
    ($ident:ident, $len:expr) => {

        // implement `AsRef` to allow converions to byte-slice.
        impl AsRef<[u8]> for $ident {
            fn as_ref(&self) -> &[u8] {
                &self.0 
            }
        }

        // implement `From` for easy conversion from
        // byte-arrays of the appropriate size.
        impl From<[u8; $len]> for $ident {
            fn from(itm: [u8; $len]) -> Self { 
                $ident(itm) 
            }
        }

        // implement `Deref` for easy interop with methods which
        // expect to be passed the enclosing byte-array directly.
        impl $crate::std::ops::Deref for $ident {
            type Target = [u8;$len];
            fn deref(&self) -> &Self::Target { 
                &self.0
            }
        }
    }
}


macro_rules! impl_byte_array_ext {
    ($ident: ident, $len:expr) => {
        // manually implemented `Clone` trait for easy copying.
        impl Clone for $ident {
            fn clone(&self) -> Self {
                let mut buf = [0u8;$len];
                for (idx,itm) in self.as_ref().iter().enumerate() {
                    buf[idx] = *itm;
                }
                buf.into()
            }
        }

        // manually implemented `Debug` trait for printouts.
        impl $crate::std::fmt::Debug for $ident {
            fn fmt(&self, f: &mut $crate::std::fmt::Formatter) -> $crate::std::fmt::Result {
                write!(f, "{}({:?})",stringify!($ident),self.as_ref())
            }
        }
    }
}


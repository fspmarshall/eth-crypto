
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

        // implement the `LowerHex` trait to allow generation
        // of lowercase hexadecimal representations.
        impl $crate::std::fmt::LowerHex for $ident {
            fn fmt(&self, f: &mut $crate::std::fmt::Formatter) -> $crate::std::fmt::Result {
                for byte in self.as_ref().iter() {
                    write!(f,"{:02x}",byte)?;
                }
                Ok(())
            }
        }


        // implement the `UpperHex` trait to allow generation
        // of uppercase hexadecimal representations.
        impl $crate::std::fmt::UpperHex for $ident {
            fn fmt(&self, f: &mut $crate::std::fmt::Formatter) -> $crate::std::fmt::Result {
                for byte in self.as_ref().iter() {
                    write!(f,"{:02X}",byte)?;
                }
                Ok(())
            }
        }


        // implement the `FromHex` trait to allow conversion from a hexadecimal string.
        impl $crate::hex::FromHex for $ident {
            type Error = $crate::types::Error;
            fn from_hex<T: AsRef<[u8]>>(s: T) -> $crate::std::result::Result<Self,Self::Error> {
                let raw = s.as_ref();
                let pfx = "0x".as_bytes();
                let hex = if raw.starts_with(pfx) { &raw[2..] } else { raw };
                if hex.len() == $len * 2 {
                    let bytes: Vec<u8> = $crate::hex::FromHex::from_hex(hex)?;
                    let mut buff = [0u8;$len];
                    for (idx,val) in bytes.into_iter().enumerate() {
                        buff[idx] = val;
                    }
                    Ok(buff.into())
                } else {
                    Err($crate::hex::FromHexError::InvalidHexLength.into())
                }
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

        // manuall implement `Default` trait for getting empty instances.
        impl Default for $ident {
            fn default() -> Self {
                $ident([0u8;$len])
            }
        }

        // manually implemented `Debug` trait for printouts.
        impl $crate::std::fmt::Debug for $ident {
            fn fmt(&self, f: &mut $crate::std::fmt::Formatter) -> $crate::std::fmt::Result {
                write!(f, "{}({:?})",stringify!($ident),self.as_ref())
            }
        }

        // manually implement `PartialEq` for comparison operations.
        impl $crate::std::cmp::PartialEq for $ident {
            fn eq(&self, other: &$ident) -> bool {
                self.as_ref() == other.as_ref()
            }
        }

        // manually flag type as `Eq` for full equivalence relations.
        impl $crate::std::cmp::Eq for $ident { }
    }
}



#[cfg(test)]
mod tests {
    use hex::FromHex;
    struct T4([u8;4]);
    impl_byte_array!(T4,4);

    #[test]
    fn fromhex_succeed() {
        let t4 = T4::from_hex("0xffaaffaa").unwrap();
        assert_eq!(t4.as_ref(),&[0xff,0xaa,0xff,0xaa]);
        let t4p = T4::from_hex("abcdef12").unwrap();
        assert_eq!(t4p.as_ref(),&[0xab,0xcd,0xef,0x12]);
    }

    #[test]
    #[should_panic]
    fn fromhex_fail() {
        let _ = T4::from_hex("0xabcdef").unwrap();
    }
}


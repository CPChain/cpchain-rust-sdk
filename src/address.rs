use std::fmt::Display;

use web3::{types::H160};

use crate::utils::{self, checksum_encode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub h160: H160,
}

impl Address {
    pub fn new(h160: H160) -> Self {
        Self { h160 }
    }
    pub fn from_str(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = utils::hex_to_bytes(s)?;
        Ok(Self {
            h160: H160::from_slice(data.as_slice()),
        })
    }
    pub fn to_checksum(&self) -> String {
        checksum_encode(&self.h160)
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_checksum())
    }
}

#[cfg(test)]
mod tests {
    use crate::address::{checksum_encode, Address};

    #[test]
    fn test_checksum() {
        fn it(addr: &str) {
            let a = Address::from_str(addr).unwrap();
            let checksum_addr = checksum_encode(&a.h160);
            assert!(checksum_addr == addr.to_string());
        }
        it("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        it("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
        it("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");
        it("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");
    }
}

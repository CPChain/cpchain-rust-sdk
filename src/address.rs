use web3::{signing, types::H160};

use crate::utils;

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

/// Generate Checksum address from address
/// https://eips.ethereum.org/EIPS/eip-55
fn checksum_encode(addr: &H160) -> String {
    let hex_addr = hex::encode(addr.as_fixed_bytes());
    let hashed = signing::keccak256(hex_addr.as_bytes());
    let hashed = hex::encode(&hashed);
    let mut result = String::new();
    for (index, ch) in hex_addr.as_bytes().iter().enumerate() {
        let ch = *ch as char;
        if ch >= '0' && ch <= '9' {
            result.push(ch);
        } else if ch >= 'a' && ch <= 'f' {
            let nibble = &hashed[index..index + 1];
            let nibble_num = i64::from_str_radix(nibble, 16).unwrap();
            if nibble_num > 7 {
                result.push(ch.to_ascii_uppercase());
            } else {
                result.push(ch)
            }
        }
    }
    format!("0x{}", result)
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

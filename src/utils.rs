use web3::{types::H160, signing};


pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut s = hex.to_string();
    if s.starts_with("0x") {
        s = s.trim_start_matches("0x").to_string();
    }
    match hex::decode(s) {
        Ok(d) => Ok(d),
        Err(err) => Err(err.into()),
    }
}

/// Generate Checksum address from address
/// https://eips.ethereum.org/EIPS/eip-55
pub fn checksum_encode(addr: &H160) -> String {
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
    use super::hex_to_bytes;

    #[test]
    fn test_hex() {
        let s = "0x0123456789abcdef";
        let d = hex_to_bytes(s);
        assert!(!d.is_err());
        let d = d.unwrap();
        assert!(d.len() * 2 == (s.len() - 2));
        assert!(d[0] == 1);
        assert!(d.last().unwrap().clone() == 239);
        let s = "0123456789abcdef";
        let d = hex_to_bytes(s);
        assert!(!d.is_err());
        let d = d.unwrap();
        assert!(d.len() * 2 == s.len());
        assert!(d[0] == 1);
        assert!(d.last().unwrap().clone() == 239);
    }
}


pub fn hex_to_u64(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut s = hex.to_string();
    if s.starts_with("0x") {
        s = s.trim_start_matches("0x").to_string();
    }
    match hex::decode(s) {
        Ok(d) => Ok(d),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::hex_to_u64;

    #[test]
    fn test_hex() {
        let s = "0x0123456789abcdef";
        let d = hex_to_u64(s);
        assert!(!d.is_err());
        let d = d.unwrap();
        assert!(d.len() * 2 == (s.len() - 2));
        assert!(d[0] == 1);
        assert!(d.last().unwrap().clone() == 239);
        let s = "0123456789abcdef";
        let d = hex_to_u64(s);
        assert!(!d.is_err());
        let d = d.unwrap();
        assert!(d.len() * 2 == s.len());
        assert!(d[0] == 1);
        assert!(d.last().unwrap().clone() == 239);
    }
}

use crate::types;

pub struct TypeHelper {}

impl TypeHelper {
    pub fn p_h160_2_c(v: &primitive_types::H160) -> types::H160 {
        types::H160::from_slice(v.as_bytes())
    }
    pub fn p_u256_2_c(v: &primitive_types::U256) -> types::U256 {
        let mut bytes: [u8; 32] = [0; 32];
        v.to_big_endian(&mut bytes);
        types::U256::from_big_endian(&bytes)
    }
    pub fn c_h160_2_p(v: &types::H160) -> primitive_types::H160 {
        primitive_types::H160::from_slice(v.as_bytes())
    }
    pub fn c_u256_2_p(v: &types::U256) -> primitive_types::U256 {
        let mut bytes: [u8; 32] = [0; 32];
        v.to_big_endian(&mut bytes);
        primitive_types::U256::from_big_endian(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::{utils, types::{H160, U256}, helpers::TypeHelper};

    #[test]
    fn test_h160() {
        fn it(s: &str) {
            let data = utils::hex_to_bytes(s).unwrap();
            let h1 = H160::from_slice(data.as_slice());
            let h160 = primitive_types::H160::from_slice(data.as_slice());
            let h2 = TypeHelper::p_h160_2_c(&h160);
            assert_eq!(h1, h2);
        }
        it("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        it("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
        it("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");
        it("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");
    }

    #[test]
    fn test_u256() {
        fn it(v: u128) {
            let h1 = U256::from(v);
            let h = primitive_types::U256::from(v);
            let h2 = TypeHelper::p_u256_2_c(&h);
            assert_eq!(h1, h2);
        }
        it(1000);
        it(100000);
        it(1000000000);
    }
}

use web3::types::{H160};

use crate::utils;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub h160: H160
}

impl Address {
    pub fn new(h160: H160) -> Self {
        Self { h160 }
    }
    pub fn from_str(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = utils::hex_to_bytes(s)?;
        Ok(Self {
            h160: H160::from_slice(data.as_slice())
        })
    }
}

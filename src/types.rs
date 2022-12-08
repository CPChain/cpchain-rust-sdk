use std::str::FromStr;

use web3::types::{U64, H160};

use crate::utils;

pub struct Address {
    pub h160: H160
}

impl Address {
    pub fn from_str(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = utils::hex_to_u64(s)?;
        Ok(Self {
            h160: H160::from_slice(data.as_slice())
        })
    }
}

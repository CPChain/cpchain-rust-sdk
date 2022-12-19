use crate::address::Address;

pub type Result = web3::Result;
pub type U256 = web3::types::U256;
pub type Bytes = web3::types::Bytes;

pub struct TransactionParameters {
    /// Transaction nonce (None for account transaction count)
    pub nonce: u64,
    /// To address
    pub to: Address,
    /// Supplied gas
    pub gas: U256,
    /// Gas price (None for estimated gas price)
    pub gas_price: U256,
    /// Transferred value
    pub value: U256,
    /// Data
    pub data: Bytes,
    /// The chain ID (None for network ID)
    pub chain_id: u64,
}

impl TransactionParameters {
    pub fn new(chain_id: u64, nonce: u64, to: Address, gas: U256, gas_price: U256, value: U256, data: Bytes) -> TransactionParameters {
        Self {
            nonce,
            to,
            gas,
            gas_price,
            value,
            data,
            chain_id
        }
    }
    pub fn to_web3_transaction(&self) -> web3::types::TransactionParameters {
        let mut tp = web3::types::TransactionParameters::default();
        tp.nonce = Some(self.nonce.into());
        tp.to = Some(self.to.h160);
        tp.gas = self.gas.into();
        tp.gas_price = self.gas_price.into();
        tp.value = self.value.into();
        tp.data = self.data.clone();
        tp.chain_id = self.chain_id.into();
        tp.transaction_type = Some(0.into());
        tp
    }
}

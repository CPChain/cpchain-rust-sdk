use rlp::RlpStream;
use web3::{signing::{self, Signature}, types::SignedTransaction};

use crate::address::Address;

pub type Result = web3::Result;
pub type U256 = web3::types::U256;
pub type Bytes = web3::types::Bytes;

pub struct TransactionParameters {
    /// Transaction nonce (None for account transaction count)
    pub nonce: U256,
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
    pub fn new(
        chain_id: u64,
        nonce: U256,
        to: Address,
        gas: U256,
        gas_price: U256,
        value: U256,
        data: Bytes,
    ) -> TransactionParameters {
        Self {
            nonce,
            to,
            gas,
            gas_price,
            value,
            data,
            chain_id,
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
    fn rlp_append_legacy(&self, stream: &mut RlpStream) {
        // transactinon type for CPChain
        stream.append(&U256::from(0));
        stream.append(&self.nonce);
        stream.append(&self.gas_price);
        stream.append(&self.gas);
        stream.append(&self.to.h160);
        stream.append(&self.value);
        stream.append(&self.data.0);
    }
    fn rlp_append_signature(&self, stream: &mut RlpStream, signature: &Signature) {
        stream.append(&signature.v);
        stream.append(&U256::from_big_endian(signature.r.as_bytes()));
        stream.append(&U256::from_big_endian(signature.s.as_bytes()));
    }
    fn encode(&self, chain_id: u64, signature: Option<&Signature>) -> RlpStream {
        let mut stream = RlpStream::new();
        stream.begin_list(10);

        self.rlp_append_legacy(&mut stream);

        if let Some(signature) = signature {
            self.rlp_append_signature(&mut stream, signature);
        } else {
            stream.append(&chain_id);
            stream.append(&0u8);
            stream.append(&0u8);
        }
        stream
    }
    pub fn sign(&self, sign: impl signing::Key) -> SignedTransaction {
        let encoded = self.encode(self.chain_id, None).out().to_vec();

        let hash = signing::keccak256(encoded.as_ref());

        let signature = sign.sign(&hash, Some(self.chain_id)).expect("hash is non-zero 32-bytes; qed");

        let signed = self.encode(self.chain_id, Some(&signature)).out().to_vec();
        let transaction_hash = signing::keccak256(signed.as_ref()).into();

        SignedTransaction {
            message_hash: hash.into(),
            v: signature.v,
            r: signature.r,
            s: signature.s,
            raw_transaction: signed.into(),
            transaction_hash,
        }
    }
}

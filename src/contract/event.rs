use web3::types::Log;

use crate::{types::{H256, U256, H160, U64}, error::StdError};

/// Event parameters
#[derive(Debug, Clone)]
pub enum EventParam {
    Address(H256),
    U256(U256),
}

#[derive(Debug, Clone)]
pub struct Event {
    pub contract_address: H160,
    pub signature: H256,
    pub params: Vec<EventParam>,
    pub block_number: U64,
    pub transaction_index: U64,
    pub log_index: U256,
    pub tx_hash: H256,
}

impl Event {
    pub fn from(log: &Log) -> Result<Self, StdError> {
        let params = Vec::new();
        Ok(Self {
            contract_address: log.address,
            signature: log.topics[0],
            params,
            block_number: log.block_number.unwrap_or(0.into()),
            transaction_index: log.transaction_index.unwrap_or(0.into()),
            log_index: log.log_index.unwrap_or(0.into()),
            tx_hash: log.transaction_hash.unwrap(),
        })
    }

    pub fn from_logs(logs: &Vec<Log>) -> Result<Vec<Self>, StdError> {
        let mut events = Vec::new();
        for log in logs.iter() {
            events.push(Event::from(&log)?);
        }
        Ok(events)
    }
}

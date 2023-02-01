use std::slice::Iter;

use web3::{types::Log, ethabi::{self, ParamType}};

use crate::{types::{H256, U256, H160, U64}, error::StdError};

/// Event parameters
#[derive(Debug, Clone)]
pub enum EventParam {
    Address(H160),
    U256(U256),
}

impl EventParam {
    pub fn from_topic(param: &ethabi::EventParam, topic: H256) -> Result<EventParam, StdError> {
        match param.kind {
            ParamType::Address => {
                Ok(EventParam::Address(topic.into()))
            },
            ParamType::Uint(size) => {
                match size {
                    _ => Err(format!("Unsupported event parameter's kind: u{:?}", size).into())
                }
            }
            _ => Err(format!("Unsupported event parameter's kind: {:?}", param.kind).into())
        }
    }
    pub fn from_bytes(param: &ethabi::EventParam, bytes: &mut Iter<u8>) -> Result<Self, StdError> {
        match param.kind {
            ParamType::Address => {
                let bytes: Vec<u8> = bytes.take(32).map(|u| u.clone()).collect();
                Ok(EventParam::Address(H160::from(H256::from_slice(bytes.as_slice()))))
            }
            ParamType::Uint(size) => {
                match size {
                    256 => {
                        let bytes: Vec<u8> = bytes.take(32).map(|u| u.clone()).collect();
                        Ok(EventParam::U256(U256::from(bytes.as_slice())))
                    }
                    _ => Err(format!("Unsupported event parameter's kind: u{:?}", size).into())
                }
            }
            _ => Err(format!("Unsupported event parameter's kind: {:?}", param.kind).into())
        }
    }
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
    pub fn from(event: &ethabi::Event, log: &Log) -> Result<Self, StdError> {
        let mut params = Vec::new();
        let mut current: usize = 0;
        let data = log.data.0.clone();
        let mut it = data.iter();
        // topics
        for i in 1..log.topics.len() {
            let topic = log.topics[i];
            let param = &event.inputs[current];
            let param = EventParam::from_topic(param, topic)?;
            params.push(param);
            current += 1;
        }
        while current < event.inputs.len() {
            let param = &event.inputs[current];
            let param = EventParam::from_bytes(param, &mut it)?;
            params.push(param);
            current += 1;
        }
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

    pub fn from_logs(event: &ethabi::Event, logs: &Vec<Log>) -> Result<Vec<Self>, StdError> {
        let mut events = Vec::new();
        for log in logs.iter() {
            events.push(Event::from(event, &log)?);
        }
        Ok(events)
    }
}

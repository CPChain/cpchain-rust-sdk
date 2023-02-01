use web3::{types::Log, ethabi::{self, ParamType}};

use crate::{types::{H256, U256, H160, U64}, error::StdError};

/// Event parameters
#[derive(Debug, Clone)]
pub enum EventParam {
    Address(H160),
    U256(U256),
    U128(u128),
    U64(u64),
    U32(u32),
    U16(u16),
    U8(u8),
    String(String),
    Bool(bool)
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
    fn take_index<'a>(index: &usize, bytes: &'a Vec<u8>) -> &'a [u8] {
        let begin = index * 32;
        let bytes: &[u8] = &bytes[begin..begin+32];
        bytes
    }
    pub fn from_bytes(param: &ethabi::EventParam, index: usize, bytes: &Vec<u8>) -> Result<Self, StdError> {
        match param.kind {
            ParamType::Address => {
                Ok(EventParam::Address(H160::from(H256::from_slice(EventParam::take_index(&index, bytes)))))
            }
            ParamType::Uint(size) => {
                match size {
                    256 => {
                        Ok(EventParam::U256(U256::from(EventParam::take_index(&index, bytes))))
                    }
                    128 => {
                        Ok(EventParam::U128(U256::from(EventParam::take_index(&index, bytes)).as_u128()))
                    }
                    64 => {
                        Ok(EventParam::U64(U256::from(EventParam::take_index(&index, bytes)).as_u64()))
                    }
                    32 => {
                        Ok(EventParam::U32(U256::from(EventParam::take_index(&index, bytes)).as_u32()))
                    }
                    16 => {
                        Ok(EventParam::U16(U256::from(EventParam::take_index(&index, bytes)).as_usize() as u16))
                    }
                    8 => {
                        Ok(EventParam::U8(U256::from(EventParam::take_index(&index, bytes)).as_usize() as u8))
                    }
                    _ => Err(format!("Unsupported event parameter's kind: u{:?}", size).into())
                }
            }
            ParamType::String => {
                // Get begin
                let begin = U256::from(EventParam::take_index(&index, bytes));
                let index = begin.as_usize() / 32;
                let length = U256::from(EventParam::take_index(&index, bytes)).as_usize();
                let start = (index + 1) * 32;
                let bytes = &bytes[start..(start + length)];
                Ok(EventParam::String(String::from_utf8_lossy(bytes).to_string()))
            }
            ParamType::Bool => {
                Ok(EventParam::Bool(U256::from(EventParam::take_index(&index, bytes)).as_usize() == 1))
            }
            _ => Err(format!("Unsupported event parameter's kind: {:?}", param.kind).into())
        }
    }
}

/// Event
/// 
/// https://goethereumbook.org/zh/event-read/
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
        let data = &log.data.0;

        // topics
        for i in 1..log.topics.len() {
            let topic = log.topics[i];
            let param = &event.inputs[current];
            let param = EventParam::from_topic(param, topic)?;
            params.push(param);
            current += 1;
        }
        // Parse data
        while current < event.inputs.len() {
            let param = &event.inputs[current];
            let index = current + 1 - log.topics.len();
            let param = EventParam::from_bytes(param, index, data)?;
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

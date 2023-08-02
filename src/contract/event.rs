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
    I8(i8),
    I32(i32),
    String(String),
    Bool(bool),
    Array(Vec<EventParam>)
}

impl EventParam {
    pub fn from_topic(param: &ethabi::EventParam, topic: H256) -> Result<EventParam, StdError> {
        match param.kind {
            ParamType::Address => {
                Ok(EventParam::Address(topic.into()))
            },
            ParamType::Uint(size) => {
                match size {
                    256 => {
                        Ok(EventParam::U256(U256::from(topic.0)))
                    }
                    128 => {
                        Ok(EventParam::U128(U256::from(topic.0).as_u128()))
                    }
                    64 => {
                        Ok(EventParam::U64(U256::from(topic.0).as_u64()))
                    }
                    32 => {
                        Ok(EventParam::U32(U256::from(topic.0).as_u64() as u32))
                    }
                    16 => {
                        Ok(EventParam::U16(U256::from(topic.0).as_u64() as u16))
                    }
                    8 => {
                        Ok(EventParam::U8(U256::from(topic.0).as_u64() as u8))
                    }
                    _ => Err(format!("Unsupported event(from topic) parameter's kind: u{:?}", size).into())
                }
            }
            _ => Err(format!("Unsupported event(from topic) parameter's kind: {:?}", param.kind).into())
        }
    }
    fn take_index<'a>(index: &usize, bytes: &'a Vec<u8>) -> &'a [u8] {
        let begin = index * 32;
        let bytes: &[u8] = &bytes[begin..begin+32];
        bytes
    }
    fn take_index2<'a>(begin: usize, bytes: &'a Vec<u8>) -> &'a [u8] {
        let end = begin + 32;
        let bytes: &[u8] = &bytes[begin..end];
        bytes
    }
    pub fn from_bytes(param: &ethabi::EventParam, index: usize, bytes: &Vec<u8>) -> Result<Self, StdError> {
        match param.kind.clone() {
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
            ParamType::Int(size) => {
                match size {
                    32 => {
                        let i = EventParam::take_index(&index, bytes);
                        let size = i.len();
                        Ok(EventParam::I32(i32::from_be_bytes([i[size-4], i[size-3], i[size-2], i[size-1]])))
                    }
                    8 => {
                        let i = EventParam::take_index(&index, bytes);
                        Ok(EventParam::I8(i8::from_be_bytes([i[i.len()-1]; 1])))
                    }
                    _ => Err(format!("Unsupported event parameter's kind: i{:?}", size).into())
                }
            }
            ParamType::String => {
                // Get begin
                let begin = U256::from(EventParam::take_index(&index, bytes));
                let length = U256::from(EventParam::take_index2(begin.as_usize(), bytes));
                let length = length.as_usize();
                let start = begin.as_usize() + 32;
                let bytes = &bytes[start..(start + length)];
                Ok(EventParam::String(String::from_utf8_lossy(bytes).to_string()))
            }
            ParamType::Bool => {
                Ok(EventParam::Bool(U256::from(EventParam::take_index(&index, bytes)).as_usize() == 1))
            }
            ParamType::Array(arr) => {
                // 拿到偏移量
                let begin = U256::from(EventParam::take_index(&index, bytes));
                // 拿到数组元素个数
                let length = U256::from(EventParam::take_index2(begin.as_usize(), bytes));
                let length = length.as_usize();
                match arr.as_ref() {
                    ParamType::FixedArray(_t, size) => {
                        // 获取第二维数组的 begin
                        let mut results: Vec<EventParam> = vec![];
                        for i in 0..length {
                            // 拿到相对偏移量
                            let b1 = U256::from(EventParam::take_index2(begin.as_usize() + (32 * (i + 1)), bytes));
                            // 拿到真实偏移量
                            let b1 = begin.as_usize() + (32 * ( 1)) + b1.as_usize();
                            match _t.as_ref() {
                                ParamType::String => {
                                    let mut r: Vec<EventParam> = vec![];
                                    for j in 0..size.clone() {
                                        // 拿到具体元素偏移量
                                        let b2 = U256::from(EventParam::take_index2(b1 + (32 * j), bytes));
                                        let b2 = b1 + b2.as_usize();
                                        // 拿到具体元素长度
                                        let length = U256::from(EventParam::take_index2(b2, bytes));
                                        let length = length.as_usize();
                                        let start = b2 + 32;
                                        let bytes = &bytes[start..(start + length)];
                                        let s = String::from_utf8_lossy(bytes).to_string();
                                        r.push(EventParam::String(s));
                                    }
                                    results.push(EventParam::Array(r));
                                },
                                _ => {
                                    return Err(format!("Unsupported event parameter's kind: {:?} of an event fixed array", param.kind).into())
                                }
                            };
                        }
                        return Ok(EventParam::Array(results))
                    },
                    _ => {
                        return Err(format!("Unsupported event parameter's kind: {:?} of an event array", param.kind).into())
                    }
                };
            }
            _ => Err(format!("Unsupported event parameter's kind: {:?}", param.kind).into())
        }
    }
}

/// Event
/// 
/// https://goethereumbook.org/zh/event-read/
/// https://docs.soliditylang.org/zh/v0.8.16/abi-spec.html
#[derive(Debug, Clone)]
pub struct Event {
    pub name: String,
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
            name: event.name.clone(),
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
            // println!("--->>> {}", hex::encode(&log.data.0.clone().to_vec()));
            events.push(Event::from(event, &log)?);
        }
        Ok(events)
    }
}

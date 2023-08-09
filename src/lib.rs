#[cfg(feature="web3")]
pub use crate::cpc_web3::CPCWeb3;

pub mod types;
#[cfg(feature="web3")]
mod cpc_web3;
#[cfg(feature="web3")]
mod transport;
#[cfg(feature="web3")]
pub mod address;
#[cfg(feature="web3")]
mod utils;
#[cfg(feature="web3")]
pub mod contract;
#[cfg(feature="web3")]
pub mod cpc_aes;
#[cfg(feature="web3")]
pub mod keystore;
#[cfg(feature="web3")]
pub mod hd;
#[cfg(feature="web3")]
pub mod accounts;
#[cfg(feature="web3")]
pub mod error;

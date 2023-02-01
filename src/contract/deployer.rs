use std::{future::Future, time, collections::HashMap};

use web3::{contract::{tokens::Tokenize}, types::{TransactionRequest, TransactionReceipt, Bytes}, ethabi::{self}, api::{Eth}};

use crate::{CPCWeb3, types::{Options, TransactionParameters}, address::Address, error::StdError, accounts::Account, transport::CPCHttp};

use super::Contract;

#[derive(Debug, Clone)]
pub struct Deployer<'a> {
    pub(crate) web3: &'a CPCWeb3,
    pub(crate) eth: Eth<CPCHttp>,
    pub(crate) abi: ethabi::Contract,
    opts: Options,
    #[allow(dead_code)]
    pub(crate) confirmations: usize,
    #[allow(dead_code)]
    pub(crate) poll_interval: time::Duration,
    pub(crate) linker: HashMap<String, Address>,
}

impl<'a> Deployer<'a> {
    pub fn new(web3: &'a CPCWeb3, abi_json: &'a [u8]) -> Self {
        let abi = ethabi::Contract::load(abi_json).unwrap();
        let eth = web3.web3.eth();
        Self {
            eth,
            abi,
            opts: Options::default(),
            confirmations: 1,
            poll_interval: time::Duration::from_secs(7),
            linker: HashMap::default(),
            web3,
        }
    }
    pub fn options(mut self, options: Options) -> Self {
        self.opts = options;
        self
    }
    async fn do_execute<P, V, Ft>(
        self,
        code: V,
        params: P,
        from: &Address,
        send: impl FnOnce(TransactionRequest) -> Ft,
    ) -> Result<Contract, StdError>
    where
        P: Tokenize,
        V: AsRef<str>,
        Ft: Future<Output = Result<TransactionReceipt, StdError>>,
    {
        let options = self.opts;
        let eth = self.eth;
        let abi = self.abi;

        let mut code_hex = code.as_ref().to_string();

        for (lib, address) in self.linker {
            if lib.len() > 38 {
                return Err("The library name should be under 39 characters.".into());
            }
            let replace = format!("__{:_<38}", lib); // This makes the required width 38 characters and will pad with `_` to match it.
            let address: String = address.to_checksum();
            code_hex = code_hex.replacen(&replace, &address, 1);
        }
        code_hex = code_hex.replace("\"", "").replace("0x", ""); // This is to fix truffle + serde_json redundant `"` and `0x`
        let code =
            hex::decode(&code_hex).map_err(|e| ethabi::Error::InvalidName(format!("hex decode error: {}", e)))?;

        let params = params.into_tokens();
        let data = match (abi.constructor(), params.is_empty()) {
            (None, false) => {
                return Err("Constructor is not defined in the ABI.".into());
            }
            (None, true) => code,
            (Some(constructor), _) => constructor.encode_input(code, &params)?,
        };

        let tx = TransactionRequest {
            from: from.h160,
            to: None,
            gas: options.gas,
            gas_price: options.gas_price,
            value: options.value,
            nonce: options.nonce,
            data: Some(Bytes(data)),
            condition: options.condition,
            transaction_type: options.transaction_type,
            access_list: options.access_list,
            max_fee_per_gas: options.max_fee_per_gas,
            max_priority_fee_per_gas: options.max_priority_fee_per_gas,
        };
        let receipt = send(tx).await?;
        match receipt.status {
            Some(status) if status == 0.into() => Err(format!("Status is zero, contract deploy failed: {}", receipt.transaction_hash).into()),
            // If the `status` field is not present we use the presence of `contract_address` to
            // determine if deployment was successfull.
            _ => match receipt.contract_address {
                Some(address) => Ok(Contract::new(web3::contract::Contract::new(eth, address, abi))),
                None => Err(format!("Contract address is none, contract deploy failed: {}", receipt.transaction_hash).into()),
            },
        }
    }
    pub async fn sign_with_key_and_execute<P, V>(
        self,
        code: V,
        params: P,
        from: &Account,
        chain_id: Option<u64>,
    ) -> Result<Contract, StdError>
    where
        P: Tokenize,
        V: AsRef<str>
    {
        let web3 = self.web3.clone();

        match self.do_execute(code, params, &from.address, move |tx| async move {
            let nonce = match tx.nonce {
                Some(nonce) => nonce,
                None => {
                    web3.transaction_count(&from.address).await?
                }
            };
            let tx = TransactionParameters::new(
                chain_id.unwrap_or(337),
                nonce,
                tx.to,
                tx.gas.unwrap_or_else(|| 1_000_000.into()),
                tx.gas_price.unwrap(),
                tx.value.unwrap_or_else(|| 0.into()),
                tx
                .data
                .expect("Tried to deploy a contract but transaction data wasn't set")
            );
            let signed_tx = web3.sign_transaction(&from, &tx).await.unwrap();
            let tx_hash = web3.submit_signed_raw_tx(&signed_tx).await.unwrap();
            web3.wait_tx(&tx_hash).await
        }).await {
            Ok(r) => Ok(r),
            Err(err) => Err(format!("Error: {}", err).into())
        }
    }
}

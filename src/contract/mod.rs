use std::future::Future;

use web3::{
    contract::tokens::{Detokenize, Tokenize},
    ethabi, types::{FilterBuilder, Log},
};

use crate::{
    accounts::Account,
    address::Address,
    transport::CPCHttp,
    types::{Bytes, Options, TransactionParameters, H256, TransactionLog},
    CPCWeb3, error::StdError,
};

use self::{deployer::Deployer, event::Event};

mod deployer;
pub mod event;

pub struct Contract {
    pub(crate) contract: web3::contract::Contract<CPCHttp>,
}

impl Contract {
    pub(crate) fn new(contract: web3::contract::Contract<CPCHttp>) -> Self {
        Self { contract }
    }
    pub fn from_address(web3: &CPCWeb3, address: &Address, abi_json: &[u8]) -> Self {
        let abi = ethabi::Contract::load(abi_json).unwrap();
        let eth = web3.web3.eth();
        Contract::new(web3::contract::Contract::new(eth, address.h160, abi))
    }
    pub fn event_sig(&self, event: &str) -> Option<H256> {
        match self.contract.abi().event(event) {
            Ok(e) => Some(e.signature()),
            Err(_) => None
        }
    }
    /// Deploy smart contract
    /// e.g.
    /// ```rust
    /// let bytecode = include_str!("../../fixtures/contracts/Metacoin.bin").trim_end();
    /// let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
    /// let account = load_account();
    /// assert_eq!(
    ///     account.address.to_checksum(),
    ///     "0x6CBea203F4061855247cea3843E2e5957C4CD428"
    /// );
    /// let balance = web3.balance(&account.address).await.unwrap();
    /// println!("balance: {:?}", balance);
    /// let c = Contract::deploy(
    ///     &web3,
    ///     include_bytes!("../../fixtures/contracts/Metacoin.abi"),
    /// )
    /// .options(Options::with(|opt| {
    ///     opt.value = Some(0.into());
    ///     opt.gas_price = Some((180_000_000_000 as u64).into());
    ///     opt.gas = Some(300_000.into());
    /// }))
    /// .sign_with_key_and_execute(bytecode, (), &account, 337.into())
    /// .await
    /// .unwrap();
    /// println!("Address: {:?}", c.address());
    /// ```
    pub fn deploy<'a>(web3: &'a CPCWeb3, abi_json: &'a [u8]) -> Deployer<'a> {
        Deployer::new(web3, abi_json)
    }
    /// Get address of this contract
    pub fn address(&self) -> Address {
        Address::new(self.contract.address())
    }
    /// Call query methods of the smart contract
    /// e.g.
    /// ```rust
    /// let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
    /// let account = load_account();
    /// let c = Contract::from_address(
    ///     &web3,
    ///     &Address::from_str("0x8b3b22339466a3c8fd9b78c309aebfbf0bb95a9a").unwrap(),
    ///     include_bytes!("../../fixtures/contracts/Metacoin.abi"),
    /// );
    /// let r = c.query(
    ///         "getBalance",
    ///     (account.address.h160,),
    ///     None,
    ///     Options::default(),
    ///     None,
    /// );
    /// let balance: U256 = r.await.unwrap();
    /// println!("balance: {:?}", balance);
    /// ```
    pub fn query<R, A, B, P>(
        &self,
        func: &str,
        params: P,
        from: A,
        options: Options,
        block: B,
    ) -> impl Future<Output = web3::contract::Result<R>> + '_
    where
        R: Detokenize,
        A: Into<Option<web3::types::Address>>,
        B: Into<Option<web3::types::BlockId>>,
        P: Tokenize,
    {
        self.contract.query(func, params, from, options, block)
    }

    /// Call functions of this contract
    pub async fn signed_call(
        &self,
        web3: &CPCWeb3,
        chain_id: u32,
        func: &str,
        params: impl Tokenize,
        options: Options,
        account: &Account,
    ) -> web3::contract::Result<H256> {
        // let signed = self.sign(func, params, options, key).await?;
        let fn_data = self
            .contract
            .abi()
            .function(func)
            .and_then(|function| function.encode_input(&params.into_tokens()))
            // TODO [ToDr] SendTransactionWithConfirmation should support custom error type (so that we can return
            // `contract::Error` instead of more generic `Error`.
            .map_err(|err| web3::error::Error::Decoder(format!("{:?}", err)))?;
        let nonce = match options.nonce {
            Some(nonce) => nonce,
            None => web3.transaction_count(&account.address).await?,
        };
        let tx = TransactionParameters::new(
            chain_id.into(),
            nonce,
            Some(self.address().h160),
            options.gas.unwrap_or(300_000.into()),
            options.gas_price.unwrap_or(web3.gas_price().await?),
            options.value.unwrap_or(0.into()),
            Bytes::from(fn_data),
        );
        let signed_tx = web3.sign_transaction(&account, &tx).await?;
        let hash = web3.submit_signed_raw_tx(&signed_tx).await?;
        Ok(hash)
    }

    pub async fn logs(&self, web3: &CPCWeb3, event_name: &str, from_block: Option<u64>, to_block: Option<u64>) -> Result<Vec<Log>, StdError> {
        let sig = match self.event_sig(event_name) {
            Some(sig) => sig,
            None => return Err(format!("Not found event `{}`", event_name).into())
        };
        let mut builder = FilterBuilder::default()
            .address(vec![self.address().h160])
            .topics(
                Some(vec![sig]),
                None,
                None,
                None,
            );
        if from_block.is_some() {
            builder = builder.from_block(from_block.unwrap().into());
        }
        if to_block.is_some() {
            builder = builder.to_block(to_block.unwrap().into());
        }
        let filter = builder.build();
        match web3.web3.eth().logs(filter).await {
            Ok(logs) => Ok(logs),
            Err(e) => Err(format!("Get logs failed: {}", e).into())
        }
    }

    pub async fn events(&self, web3: &CPCWeb3, event_name: &str, from_block: Option<u64>, to_block: Option<u64>) -> Result<Vec<Event>, StdError> {
        let logs = self.logs(web3, event_name, from_block, to_block).await?;
        let e = self.contract.abi().event(event_name).unwrap();
        // 如果事件字段是 indexed 的，则会在 topics 中，其余则在 data 字段中按字节排列
        Ok(Event::from_logs(e, &logs)?)
    }

    pub fn parse_log(abi_json: &[u8], event_name: &str, log: &TransactionLog) -> Result<Event, StdError> {
        let abi = ethabi::Contract::load(abi_json)?;
        let e = abi.event(event_name)?;
        Event::from(e, &log)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{
        accounts::Account,
        types::{Options, H160, U256},
        CPCWeb3,
    };

    fn load_account() -> Account {
        Account::from_keystore(
            include_str!("../../keystore/0x6CBea203F4061855247cea3843E2e5957C4CD428.json"),
            "123456",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_deploy_contract() {
        let bytecode = include_str!("../../fixtures/contracts/Metacoin.bin").trim_end();
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let account = load_account();
        assert_eq!(
            account.address.to_checksum(),
            "0x6CBea203F4061855247cea3843E2e5957C4CD428"
        );
        let balance = web3.balance(&account.address).await.unwrap();
        println!("balance: {:?}", balance);
        let c = Contract::deploy(
            &web3,
            include_bytes!("../../fixtures/contracts/Metacoin.abi"),
        )
        .options(Options::with(|opt| {
            opt.value = Some(0.into());
            opt.gas_price = Some((180_000_000_000 as u64).into());
            opt.gas = Some(3000_000.into());
        }))
        .sign_with_key_and_execute(bytecode, (), &account, 337.into())
        .await
        .unwrap();
        println!("Address: {:?}", c.address());
        let r = c.query(
            "getBalance",
            (account.address.h160,),
            None,
            Options::default(),
            None,
        );
        let balance: U256 = r.await.unwrap();
        println!("balance: {:?}", balance);
    }

    #[tokio::test]
    async fn test_query() {
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let account = load_account();
        let c = Contract::from_address(
            &web3,
            &Address::from_str("0x18b1385f172fed71d25d4faf306fb064131e8b4c").unwrap(),
            include_bytes!("../../fixtures/contracts/Metacoin.abi"),
        );
        let r = c.query(
            "getBalance",
            (account.address.h160,),
            None,
            Options::default(),
            None,
        );
        let balance: U256 = r.await.unwrap();
        println!("balance: {:?}", balance);
    }
    #[tokio::test]
    async fn test_call() {
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let account = load_account();
        let c = Contract::from_address(
            &web3,
            &Address::from_str("0xcbefb53f853bd7ea355c1e48c250cafe60d24e67").unwrap(), // 0xdf7db491b07e8052a43095dd93385d07e7c43e6c
            include_bytes!("../../fixtures/contracts/Metacoin.abi"),
        );
        let hash = c
            .signed_call(
                &web3,
                337,
                "sendCoin",
                (
                    H160::from_str("0xFD10B944FFC7Be13516C003eeE6cEf7335d031e9").unwrap(),
                    U256::from(8),
                ),
                Options::default(),
                &account,
            )
            .await
            .unwrap();
        let receipt = web3.wait_tx(&hash).await.unwrap();
        println!("{:?}", receipt);
    }

    #[tokio::test]
    async fn test_events() {
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let c = Contract::from_address(
            &web3,
            &Address::from_str("0xcbefb53f853bd7ea355c1e48c250cafe60d24e67").unwrap(),
            include_bytes!("../../fixtures/contracts/Metacoin.abi"),
        );
        let events = c.events(&web3, "Transfer", Some(0), None).await.unwrap();
        println!("{:?}", events);
        println!("Length {:?}", events.len())
    }

    #[tokio::test]
    async fn test_term_events() {
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let c = Contract::from_address(
            &web3,
            &Address::from_str("0xd6382b0757C691cb502D0b47264F70d50F236226").unwrap(),
            include_bytes!("../../fixtures/contracts/Term.abi.json"),
        );
        let events = c.events(&web3, "TermCreated", Some(0), None).await.unwrap();
        println!("{:?}", events);
        println!("Length {:?}", events.len())
    }

    #[tokio::test]
    async fn test_roadmap_events() {
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let c = Contract::from_address(
            &web3,
            &Address::from_str("0xc3aA832c3ba3c005b93E35850874e3fD212a832C").unwrap(),
            include_bytes!("../../fixtures/contracts/Roadmap.abi.json"),
        );
        let events = c.events(&web3, "RegisterRoadmap", Some(0), None).await.unwrap();
        println!("{:?}", events);
        println!("Length {:?}", events.len())
    }

    #[tokio::test]
    async fn test_one_dime_events() {
        // 一维数组测试
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let abi = "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"xx\",\"type\":\"string[]\"}],\"name\":\"E1\",\"type\":\"event\"}]".as_bytes();
        let c = Contract::from_address(
            &web3,
            &Address::from_str("0x1DaD5F2372B463eD0Db6A8c0ba3B0b6E7196fb18").unwrap(),
            abi
        );
        let events = c.events(&web3, "E1", Some(0), None).await.unwrap();
        println!("{:?}", events);
        println!("Length {:?}", events.len())
    }
}

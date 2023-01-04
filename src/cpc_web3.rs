use std::time::{Duration, Instant};

use web3::{
    types::{Block, BlockId, SignedTransaction, Transaction, TransactionReceipt, H160, H256, U256},
    Error, Web3,
};

use crate::{
    accounts::Account, address::Address, transport::CPCHttp, types::TransactionParameters,
};

#[derive(Debug, Clone)]
pub struct CPCWeb3 {
    web3: Web3<CPCHttp>,
}

impl CPCWeb3 {
    pub fn new(url: &str) -> Result<Self, Error> {
        let transport = CPCHttp::new(url)?;
        let web3 = web3::Web3::new(transport);
        Ok(Self { web3 })
    }
    pub async fn block_number(&self) -> Result<u64, Error> {
        let current_block = self.web3.eth().block_number().await?;
        Ok(current_block.as_u64())
    }

    pub async fn block(&self, number: u32) -> Result<Option<Block<H256>>, Error> {
        self.web3.eth().block(BlockId::Number(number.into())).await
    }

    pub async fn block_with_txs(&self, number: u32) -> Result<Option<Block<Transaction>>, Error> {
        self.web3
            .eth()
            .block_with_txs(BlockId::Number(number.into()))
            .await
    }

    pub async fn balance(&self, address: Address) -> Result<U256, Error> {
        let balance = self.web3.eth().balance(address.h160, None).await?;
        Ok(balance)
    }

    pub async fn sign_transaction(
        &self,
        account: &Account,
        tx: &TransactionParameters,
    ) -> Result<SignedTransaction, Error> {
        let signed = tx.sign(&account.secret_key);
        Ok(signed)
    }

    pub async fn gas_price(&self) -> Result<U256, Error> {
        Ok(self.web3.eth().gas_price().await?)
    }

    pub async fn transaction_count(&self, address: &Address) -> Result<U256, Error> {
        self.web3.eth().transaction_count(address.h160, None).await
    }

    pub async fn submit_signed_raw_tx(&self, signed: &SignedTransaction) -> Result<H256, Error> {
        self.web3
            .eth()
            .send_raw_transaction(signed.raw_transaction.clone())
            .await
    }

    pub async fn wait_tx(
        &self,
        tx_hash: &H256,
    ) -> Result<TransactionReceipt, Box<dyn std::error::Error>> {
        let start = Instant::now();
        let timeout = Duration::from_secs(20);
        loop {
            let receipt = self.web3.eth().transaction_receipt(*tx_hash).await?;
            if receipt.is_some() {
                return Ok(receipt.unwrap());
            }
            if start.elapsed() >= timeout {
                return Err("Waiting for transaction receipt timed out".into());
            }
        }
    }

    pub async fn estimate_gas(&self, req: &TransactionParameters) -> Result<U256, Error> {
        self.web3
            .eth()
            .estimate_gas(req.to_call_request(), None)
            .await
    }

    pub async fn transaction_receipt(
        &self,
        tx_hash: &H256,
    ) -> Result<Option<TransactionReceipt>, Error> {
        self.web3.eth().transaction_receipt(*tx_hash).await
    }

    pub async fn is_contract(&self, addr: H160) -> Result<bool, Error> {
        let code = self.web3.eth().code(addr, None).await?;
        Ok(code.0.len() > 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::types::Bytes;

    use super::*;

    #[tokio::test]
    async fn test_block_number() {
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let number = web3.block_number().await.unwrap();
        println!("{:?}", number);
        assert!(number > 0);
    }

    #[tokio::test]
    async fn test_get_block_with_txs() {
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let block = web3.block_with_txs(100).await.unwrap();
        assert!(block.is_some());
        let block = block.unwrap();
        assert!(block.number.unwrap().as_u32() == 100);
        assert!(block.transactions.len() == 0);
        assert!(block.size.unwrap().as_u32() == 1263);
        assert!(block.hash.unwrap().to_string().to_lowercase() == "0x1b91…4aef");
        let block = web3.block_with_txs(10504047).await.unwrap();
        assert!(block.is_some());
        let block = block.unwrap();
        assert!(block.number.unwrap().as_u32() == 10504047);
        assert!(block.transactions.len() == 24);
        assert!(block.size.unwrap().as_u32() == 8619);
        assert!(block.hash.unwrap().to_string().to_lowercase() == "0x37e1…0e7b");
        // Check transaction
        let tx = &block.transactions[0];
        assert!(tx.hash.to_string() == "0x89cd…6ada");
        assert!(tx.from.unwrap().to_string() == "0x5e17…b6f0");
        assert!(tx.to.unwrap().to_string() == "0x2a18…fcd0");
        assert!(tx.value.to_string() == "0");
        assert!(tx.gas.to_string() == "2300000");
        assert!(tx.gas_price.unwrap().to_string() == "18000000000");
        let tx = &block.transactions.last().unwrap();
        assert!(tx.hash.to_string() == "0xc5b0…5e62");

        // Get unexists block
        let block = web3.block_with_txs(100000000).await.unwrap();
        assert!(block.is_none());
    }

    #[tokio::test]
    async fn test_get_block() {
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let block = web3.block(100).await.unwrap().unwrap();
        assert!(block.number.unwrap().as_u32() == 100);
    }

    #[tokio::test]
    async fn test_get_balance() {
        let web3 = CPCWeb3::new("http://192.168.0.164:8501").unwrap();
        let balance = web3
            .balance(Address::from_str("0x7D491C482eBa270700b584888f864177205c5159").unwrap())
            .await
            .unwrap();
        println!("{:?}", balance.as_u128());
    }

    #[tokio::test]
    async fn test_gas_price() {
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let gas_price = web3.gas_price().await.unwrap();
        assert_eq!(gas_price, U256::from(18) * U256::exp10(9))
    }

    #[tokio::test]
    async fn test_get_transactions_cnt() {
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let cnt = web3
            .transaction_count(
                &Address::from_str("0x1455D180E3adE94ebD9cC324D22a9065d1F5F575").unwrap(),
            )
            .await
            .unwrap();
        assert!(cnt >= U256::from(1065));
        let cnt = web3
            .transaction_count(
                &Address::from_str("0x2455D180E3adE94ebD9cC324D22a9065d1F5F575").unwrap(),
            )
            .await
            .unwrap();
        assert!(cnt == U256::from(0))
    }

    #[tokio::test]
    async fn test_sign_transaction() {
        let web3 = CPCWeb3::new("http://192.168.0.164:8501").unwrap();
        let account = Account::from_phrase(
            "length much pull abstract almost spin hair chest ankle harbor dizzy life",
            None,
        )
        .unwrap();
        println!("{}", account.address);
        let gas_price = web3.gas_price().await.unwrap();
        let nonce = web3.transaction_count(&account.address).await.unwrap();
        let tx_object = TransactionParameters::new(
            41,
            nonce,
            Address::from_str("0x1455D180E3adE94ebD9cC324D22a9065d1F5F575").unwrap(),
            300000.into(),
            gas_price,
            U256::exp10(17), //0.1 cpc
            Bytes::default(),
        );

        let estimated_gas = web3.estimate_gas(&tx_object).await.unwrap();
        assert_eq!(estimated_gas, U256::from(21000));

        let signed = web3.sign_transaction(&account, &tx_object).await.unwrap();
        let tx_hash = web3.submit_signed_raw_tx(&signed).await.unwrap();
        println!("{:?} {:?}", tx_hash, signed.transaction_hash);
        assert_eq!(tx_hash, signed.transaction_hash);
        // wait for transaction
        let receipt = web3.wait_tx(&tx_hash).await.unwrap();
        println!("{:?}", receipt);
    }

    #[tokio::test]
    async fn test_is_contract() {
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        assert_eq!(
            web3.is_contract(
                Address::from_str("0xcf3174cd4dc7c4834d8932f7c3800ab98afc437a")
                    .unwrap()
                    .h160
            )
            .await
            .unwrap(),
            true
        );
        assert_eq!(
            web3.is_contract(
                Address::from_str("0x1455D180E3adE94ebD9cC324D22a9065d1F5F575")
                    .unwrap()
                    .h160
            )
            .await
            .unwrap(),
            false
        );
    }
}

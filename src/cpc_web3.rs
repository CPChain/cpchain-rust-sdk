use web3::{Error, Web3, types::{BlockId, Transaction, Block, H256, U256}};

use crate::{transport::CPCHttp, address::Address};

pub struct CPCWeb3 {
    web3: Web3<CPCHttp>
}

impl CPCWeb3 {
    pub fn new(url: &str) -> Result<Self, Error> {
        // let transport = web3::transports::Http::new(url)?;
        let transport = CPCHttp::new(url)?;
        let web3 = web3::Web3::new(transport);
        Ok(Self {
            web3,
        })
    }
    pub async fn block_number(&self) -> Result<u64, Error> {
        let current_block = self.web3.eth().block_number().await?;
        Ok(current_block.as_u64())
    }

    pub async fn block(&self, number: u32) -> Result<Option<Block<H256>>, Error> {
        self.web3.eth().block(BlockId::Number(number.into())).await
    }

    pub async fn block_with_txs(&self, number: u32) -> Result<Option<Block<Transaction>>, Error> {
        self.web3.eth().block_with_txs(BlockId::Number(number.into())).await
    }

    pub async fn balance(&self, address: Address) -> Result<U256, Error> {
        let balance = self.web3.eth().balance(address.h160, None).await?;
        Ok(balance)
    }
}

#[cfg(test)]
mod tests {
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
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let balance = web3.balance(Address::from_str("0x1455D180E3adE94ebD9cC324D22a9065d1F5F575").unwrap()).await.unwrap();
        println!("{:?}", balance.as_u128());
    }

}

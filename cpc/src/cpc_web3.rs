use web3::{Error, Web3, transports::Http};

pub struct CPCWeb3 {
    web3: Web3<Http>
}

impl CPCWeb3 {
    pub fn new(url: &str) -> Result<Self, Error> {
        let transport = web3::transports::Http::new(url)?;
        let web3 = web3::Web3::new(transport);
        Ok(Self {
            web3,
        })
    }
    pub async fn block_number(&self) -> Result<u64, Error> {
        let current_block = self.web3.eth().block_number().await?;
        Ok(current_block.as_u64())
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
}

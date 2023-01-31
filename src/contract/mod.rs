use crate::CPCWeb3;

use self::deployer::Deployer;

mod deployer;

pub struct Contract {
}

impl Contract {
    pub fn deploy<'a>(web3: &'a CPCWeb3, abi_json: &'a [u8]) -> Deployer<'a> {
        Deployer::new(web3, abi_json)
    }
}

#[cfg(test)]
mod tests {
    use crate::{CPCWeb3, accounts::Account, types::{Options, TransactionParameters, U256, Bytes}, address::Address};
    use super::*;

    #[tokio::test]
    async fn test_contracts() {
        let bytecode = include_str!("../../fixtures/contracts/Metacoin.bin").trim_end();
        let web3 = CPCWeb3::new("https://civilian.cpchain.io").unwrap();
        let account = Account::from_keystore(
            include_str!("../../keystore/0x6CBea203F4061855247cea3843E2e5957C4CD428.json"), "123456").unwrap();
        assert_eq!(account.address.to_checksum(), "0x6CBea203F4061855247cea3843E2e5957C4CD428");
        let balance = web3.balance(&account.address).await.unwrap();
        println!("balance: {:?}", balance);

        // Send cpc test
        // let gas_price = web3.gas_price().await.unwrap();
        // let nonce = web3.transaction_count(&account.address).await.unwrap();
        // let tx_object = TransactionParameters::new(
        //     337,
        //     nonce,
        //     Some(Address::from_str("0x1455D180E3adE94ebD9cC324D22a9065d1F5F575").unwrap().h160),
        //     300000.into(),
        //     gas_price,
        //     U256::exp10(17), //0.1 cpc
        //     Bytes::default(),
        // );
        // let estimated_gas = web3.estimate_gas(&tx_object).await.unwrap();
        // assert_eq!(estimated_gas, U256::from(21000));

        // let signed = web3.sign_transaction(&account, &tx_object).await.unwrap();
        // let tx_hash = web3.submit_signed_raw_tx(&signed).await.unwrap();
        // println!("{:?} {:?}", tx_hash, signed.transaction_hash);
        // assert_eq!(tx_hash, signed.transaction_hash);
        // // wait for transaction
        // let receipt = web3.wait_tx(&tx_hash).await.unwrap();
        // println!("{:?}", receipt);

        Contract::deploy(&web3, include_bytes!("../../fixtures/contracts/Metacoin.abi"))
            // .confirmations(0)
            .options(Options::with(|opt| {
                opt.value = Some(0.into());
                opt.gas_price = Some((180_000_000_000 as u64).into());
                opt.gas = Some(300_000.into());
            }))
            .sign_with_key_and_execute(bytecode, (), &account, 337.into())
            .await.unwrap();
    }
}

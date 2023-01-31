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
    use crate::{CPCWeb3, accounts::Account, types::{Options}};
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

use secp256k1::{rand, Secp256k1, SecretKey, PublicKey};
use web3::{signing, types::Address as Web3Address};

use crate::{address::Address, utils};

/// Account
/// 
/// Example
/// ```rust
/// let account = Account::random();
/// // Get addres
/// println!("{}", account.address.to_checksum());
/// ```
#[derive(Debug, Clone)]
pub struct Account {
    pub secret_key: SecretKey,
    #[allow(dead_code)]
    public_key: PublicKey,
    pub address: Address,
}

fn generate_address(public_key: &PublicKey) -> Address {
    let public_key = public_key.serialize_uncompressed();
    debug_assert_eq!(public_key[0], 0x04);
    let hash = signing::keccak256(&public_key[1..]);
    let h160 = Web3Address::from_slice(&hash[12..]);
    Address::new(h160)
}

impl Account {
    fn new(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let address = generate_address(&public_key);
        Self {
            secret_key,
            public_key,
            address
        }
    }

    pub fn from_private_key(private_key: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = utils::hex_to_bytes(private_key)?;
        let secret_key = SecretKey::from_slice(&bytes)?;
        Ok(Account::new(secret_key))
    }

    pub fn random() -> Account {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        Account::new(secret_key)
    }

    pub fn private_key(&self) -> String {
        let bytes = self.secret_key.secret_bytes().to_vec();
        format!("0x{}", hex::encode(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use crate::address::Address;

    use super::Account;

    #[test]
    fn test_create_account() {
        let account = Account::random();
        assert!(account.private_key().len() == 66);
    }

    #[test]
    fn test_from_private_key() {
        let account = Account::from_private_key("0x6c0296556144bf09864f0583886867e5cb2eea02206ca7187d998529ff8ef069").unwrap();
        assert!(account.address == Address::from_str("0x7de6c6E04Ea0CDc76fD51c6F441C25a7DCA236A0").unwrap())
    }
}

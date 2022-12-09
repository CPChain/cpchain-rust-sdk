use secp256k1::{rand, Secp256k1, SecretKey, PublicKey};
use web3::{signing, types::Address as Web3Address};

use crate::types::Address;


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
    pub fn random() -> Account {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let address = generate_address(&public_key);
        Self {
            secret_key,
            public_key,
            address
        }
    }

    pub fn private_key(&self) -> String {
        let bytes = self.secret_key.secret_bytes().to_vec();
        format!("0x{}", hex::encode(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::Account;

    #[test]
    fn test_create_account() {
        let account = Account::random();
        assert!(account.private_key().len() == 66);
    }
}

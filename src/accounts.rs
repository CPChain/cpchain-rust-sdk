use bip39::Mnemonic;
use secp256k1::{rand, PublicKey, Secp256k1, SecretKey};
use web3::{signing, types::Address as Web3Address};

use crate::{address::Address, hd::HDNode, utils};

/// Account
///
/// Example
/// ```rust
/// // Default derived path is "m/44'/337'/0'/0/0"
/// let account = Account::new(None);
/// // Get addres
/// println!("{}", account.address.to_checksum());
/// ```
#[derive(Debug, Clone)]
pub struct Account {
    pub secret_key: SecretKey,
    #[allow(dead_code)]
    public_key: PublicKey,
    pub address: Address,
    pub mnemonic: Option<Mnemonic>,
}

fn generate_address(public_key: &PublicKey) -> Address {
    let public_key = public_key.serialize_uncompressed();
    debug_assert_eq!(public_key[0], 0x04);
    let hash = signing::keccak256(&public_key[1..]);
    let h160 = Web3Address::from_slice(&hash[12..]);
    Address::new(h160)
}

impl Account {
    pub fn new(derive_path: Option<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let hd_node = HDNode::new()?;
        Account::_new(derive_path, &hd_node)
    }

    fn _new(derive_path: Option<String>, hd_node: &HDNode) -> Result<Account, Box<dyn std::error::Error>> {
        let hd_node = hd_node.derive_path(
            derive_path
                .unwrap_or("m/44'/337'/0'/0/0".to_string())
                .as_str(),
        )?;
        let secret_key = SecretKey::from_slice(&hd_node.private_key.unwrap())?;
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let address = generate_address(&public_key);
        Ok(Self {
            secret_key,
            public_key,
            address,
            mnemonic: hd_node.mnemonic,
        })
    }

    pub fn from_phrase(phrase: &str, derive_path: Option<String>) -> Result<Account, Box<dyn std::error::Error>> {
        let hd_node = HDNode::from_phrase(phrase)?;
        Account::_new(derive_path, &hd_node)
    }

    fn from_secert_key(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let address = generate_address(&public_key);
        Self {
            secret_key,
            public_key,
            address,
            mnemonic: None,
        }
    }

    pub fn from_private_key(private_key: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = utils::hex_to_bytes(private_key)?;
        let secret_key = SecretKey::from_slice(&bytes)?;
        Ok(Account::from_secert_key(secret_key))
    }

    pub fn random() -> Account {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        Account::from_secert_key(secret_key)
    }

    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.secret_key.secret_bytes()
    }

    pub fn private_key(&self) -> String {
        let bytes = self.secret_key.secret_bytes().to_vec();
        format!("0x{}", hex::encode(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use bip39::{Language, Mnemonic, MnemonicType};

    use crate::address::Address;

    use super::Account;

    #[test]
    fn test_create_account() {
        let account = Account::random();
        assert!(account.private_key().len() == 66);
        let account = Account::new(None).unwrap();
        println!("{} {}", account.mnemonic.unwrap().phrase(), account.address)
    }

    #[test]
    fn test_from_phrase() {
        let account = Account::from_phrase("length much pull abstract almost spin hair chest ankle harbor dizzy life", None).unwrap();
        assert_eq!(account.address.to_checksum(), "0x7D491C482eBa270700b584888f864177205c5159");
    }

    #[test]
    fn test_from_private_key() {
        let account = Account::from_private_key(
            "0x6c0296556144bf09864f0583886867e5cb2eea02206ca7187d998529ff8ef069",
        )
        .unwrap();
        assert!(
            account.address
                == Address::from_str("0x7de6c6E04Ea0CDc76fD51c6F441C25a7DCA236A0").unwrap()
        )
    }

    #[test]
    fn test_bip39() {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        println!("{}", mnemonic.phrase());
        println!("{:?}", mnemonic.entropy().len())
    }

    #[test]
    fn test_mnemonic_of_account() {
        let addr = "0xd7998FD7F5454722a16Cd67E881CedF9896CE396";
        let private_key = "0xf07ab943a5cd880d273ec38878bfa914bbfa1fe46dc6deb78590f8ef137a0690";
        // let mnemonic = "lyrics mean wisdom census merit sample always escape spread tone pipe current";
        let account = Account::from_private_key(private_key).unwrap();
        assert!(account.address == Address::from_str(addr).unwrap());
        assert_eq!(account.mnemonic.is_none(), true);
    }
}

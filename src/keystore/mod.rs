use cpc_aes::{AESParams, AES, Mode, InitVector};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use web3::signing::keccak256;

use crate::accounts::Account;

use self::{kdf::KDF, crypto_info::{CryptoInfo, CipherParams}};

mod kdf;
mod crypto_info;

/// https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
#[derive(Serialize, Deserialize, Debug)]
pub struct Keystore {
    address: String,
    crypto: CryptoInfo,
    id: String,
    version: usize,
}

impl Keystore {
    pub fn to_string(&self) -> Result<String, Box<dyn std::error::Error>> {
        match serde_json::to_string(&self) {
            Ok(s) => return Ok(s),
            Err(e) => return Err(format!("{}", e).into()),
        }
    }

    pub fn encrypt_pbkdf2(account: &Account, password: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // KDF encryption
        let (password_hash, kdf) = KDF::PBKDF2(None).encrypt(password)?;
        let mut derived_key: [u8; 16] = [0; 16];
        password_hash[..16].iter().enumerate().for_each(|(index, elem)| {
            derived_key[index] = elem.clone();
        });
        let mut mac_prefix: [u8; 16] = [0; 16];
        password_hash[16..].iter().enumerate().for_each(|(index, elem)| {
            mac_prefix[index] = elem.clone();
        });
        // AES encrypt
        let iv = [0x24; 16];
        let params = AESParams {
            mode: Some(Mode::CTR(InitVector::I16(iv)))
        };
        let encrypted = AES::AES128(derived_key).encrypt(&account.private_key_bytes().to_vec(), &params).unwrap();
        // mac
        let mut bytes = password_hash[16..].to_vec();
        bytes.append(&mut encrypted.clone());
        let mac = keccak256(&bytes);
        // id
        let id = Uuid::new_v4();
        Ok(Self {
            address: account.address.to_string().to_lowercase(),
            crypto: CryptoInfo { 
                cipher: "aes-128-ctr".to_string(), 
                cipher_params: CipherParams { iv: hex::encode(iv) }, 
                cipher_text: hex::encode(&encrypted),
                kdf: kdf, 
                mac: hex::encode(mac),
            },
            id: id.to_string(),
            version: 3,
        })
    }

    // pub fn decrypt(json: &str, password: &str) {

    // }
}

impl From<String> for Keystore {
    fn from(s: String) -> Self {
        let ks: Keystore = serde_json::from_str(s.as_str()).unwrap();
        ks
    }
}

#[cfg(test)]
mod tests {
    use crate::keystore::kdf::{Pbkdf2Params, ScryptParams};

    use super::*;

    #[test]
    fn test_serialize() {
        // PBKDF2
        let pbkdf2_params = Pbkdf2Params {
            c: 26144,
            dklen: 32,
            prf: "hmac-sha256".to_string(),
            salt: "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd".to_string(),
        };
        let keystore = Keystore {
            address: "0x888".to_string(),
            crypto: CryptoInfo {
                cipher: "aes-128-ctr".to_string(),
                cipher_params: CipherParams {
                    iv: "83dbcc02d8ccb40e466191a123791e0e".to_string(),
                },
                cipher_text: "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c"
                    .to_string(),
                kdf: KDF::PBKDF2(Some(pbkdf2_params.clone())),
                mac: "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2".to_string(),
            },
            id: "3198bc9c-6672-5ab3-d995-4942343ae5b6".to_string(),
            version: 1,
        };
        let serialized = keystore.to_string().unwrap();
        println!("{}", serialized);

        // ScryptParams
        let scrypt_params = ScryptParams {
            dklen: 32,
            n: 262144,
            p: 8,
            r: 1,
            salt: "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19".to_string(),
        };
        let keystore = Keystore {
            address: "0x888".to_string(),
            crypto: CryptoInfo {
                cipher: "aes-128-ctr".to_string(),
                cipher_params: CipherParams {
                    iv: "83dbcc02d8ccb40e466191a123791e0e".to_string(),
                },
                cipher_text: "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c"
                    .to_string(),
                kdf: KDF::SCRYPT(Some(scrypt_params.clone())),
                mac: "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2".to_string(),
            },
            id: "3198bc9c-6672-5ab3-d995-4942343ae5b6".to_string(),
            version: 1,
        };
        let serialized = keystore.to_string().unwrap();
        println!("{}", serialized);
    }

    #[test]
    fn test_encrypt_pbkdf2() {
        let mnemonic = "lyrics mean wisdom census merit sample always escape spread tone pipe current";
        let account = Account::from_phrase(mnemonic, None).unwrap();
        let ks = Keystore::encrypt_pbkdf2(&account, "123456").unwrap();
        println!("{} {:?}", ks.crypto.cipher_text, account.private_key());
        println!("{}", ks.to_string().unwrap());
    }
}

#![feature(unchecked_math)]

use cpc_aes::{AESParams, AES, Mode, InitVector};
use rand::thread_rng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use web3::signing::keccak256;

use crate::accounts::Account;

use self::{kdf::KDF, crypto_info::{CryptoInfo, CipherParams}};

mod kdf;
mod crypto_info;
pub mod my_scrypt;
mod bits;

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

    fn derive(kdf: &KDF, password: &str) -> Result<([u8; 16], [u8; 16], KDF), Box<dyn std::error::Error>> {
        let (password_hash, kdf) = kdf.encrypt(password)?;
        let mut derived_key: [u8; 16] = [0; 16];
        password_hash[..16].iter().enumerate().for_each(|(index, elem)| {
            derived_key[index] = elem.clone();
        });
        let mut mac_prefix: [u8; 16] = [0; 16];
        password_hash[16..].iter().enumerate().for_each(|(index, elem)| {
            mac_prefix[index] = elem.clone();
        });
        Ok((derived_key, mac_prefix, kdf))
    }

    fn aes_128_ctr(derived_key: [u8; 16], data: &Vec<u8>, iv: [u8; 16]) -> Vec<u8> {
        // AES encrypt
        let params = AESParams {
            mode: Some(Mode::CTR(InitVector::I16(iv)))
        };
        let encrypted = AES::AES128(derived_key).encrypt(&data, &params).unwrap();
        encrypted
    }

    fn rand_iv() -> [u8; 16] {
        let mut iv = [0x0; 16];
        let mut rng = thread_rng();
        rng.fill_bytes(&mut iv);
        iv
    }

    fn caclute_mac(prefix: &[u8; 16], encrypted: &Vec<u8>) -> [u8; 32] {
        let mut bytes = prefix.to_vec();
        bytes.append(&mut encrypted.clone());
        let mac = keccak256(&bytes);
        mac
    }

    pub fn encrypt_pbkdf2(account: &Account, password: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // KDF encryption
        let (derived_key, mac_prefix, kdf) = Keystore::derive(&KDF::PBKDF2(None), password)?;
        // AES encrypt
        let iv = Keystore::rand_iv();
        let encrypted = Keystore::aes_128_ctr(derived_key, &account.private_key_bytes().to_vec(), iv);
        // mac
        let mac = Keystore::caclute_mac(&mac_prefix, &encrypted);
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

    pub fn decrypt(&self, password: &str) -> Result<Account, Box<dyn std::error::Error>> {
        // kdf
        let (key, mac_prefix, _) = Keystore::derive(&self.crypto.kdf, password)?;
        let bytes = hex::decode(&self.crypto.cipher_text)?;
        // caclute_mac
        let expected_mac = Keystore::caclute_mac(&mac_prefix, &bytes);
        if hex::encode(expected_mac) != self.crypto.mac {
            return Err("invalid mac".into())
        }
        // decrypt
        let mut iv:[u8; 16] = [0; 16];
        hex::decode(&self.crypto.cipher_params.iv)?.iter().enumerate().for_each(|(i, e)| {
            iv[i] = e.clone();
        });
        let decrypted = Keystore::aes_128_ctr(key, &bytes, iv);
        let account = Account::from_private_key(&hex::encode(&decrypted))?;
        let mut addr = self.address.clone();
        if !addr.starts_with("0x") {
            addr = "0x".to_string() + &addr;
        }
        if addr != account.address.to_checksum().to_lowercase() {
            return Err("address mismatch".into())
        }
        Ok(account)
    }
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
    fn test_deserialize() {
        let j = "
            {\"address\":\"0xd7998FD7F5454722a16Cd67E881CedF9896CE396\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"cipherparams\":{\"iv\":\"24242424242424242424242424242424\"},\"ciphertext\":\"9a4785cd9c59ac3550e7be9c47045e24ae93bcd85518dd510f0e83537a6b1cf7\",\"kdf\":\"pbkdf2\",\"kdfparams\":{\"c\":262144,\"dklen\":32,\"prf\":\"hmac-sha256\",\"salt\":\"6949646d3976356e2b636e74462b32476d3742465677\"},\"mac\":\"1da9056f139ee205cc342233a1bfc3fb7cbd9f4d904aa9b971e373c369aee840\"},\"id\":\"2a327cb3-776a-4a77-8cf9-66b1a615d9b5\",\"version\":3}
        ";
        let ks = Keystore::from(j.to_string());
        println!("{:?}", ks);
    }

    #[test]
    fn test_encrypt_pbkdf2() {
        let mnemonic = "lyrics mean wisdom census merit sample always escape spread tone pipe current";
        let account = Account::from_phrase(mnemonic, None).unwrap();
        let ks = Keystore::encrypt_pbkdf2(&account, "123456").unwrap();
        println!("{} {:?}", ks.crypto.cipher_text, account.private_key());
        println!("{}", ks.to_string().unwrap());
    }

    #[test]
    fn test_decrypt_pbkdf2() {
        let j = "
        {\"address\":\"0xd7998fd7f5454722a16cd67e881cedf9896ce396\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"cipherparams\":{\"iv\":\"fa9d17a51ba92d61515a6bb629ad842e\"},\"ciphertext\":\"89ad80b27d8325bf79dcef52994e8b4ea626a357120dc8fdca4f0e61058f0496\",\"kdf\":\"pbkdf2\",\"kdfparams\":{\"c\":262144,\"dklen\":32,\"prf\":\"hmac-sha256\",\"salt\":\"dc0b353e69db487ee8ea3716085fe7b6\"},\"mac\":\"e15200e3b57f22714f09629fcf98b79fd8af6f8493c663f09c771e9cb17c1075\"},\"id\":\"83798882-4537-41ae-b205-30b032f2c88d\",\"version\":3}
        ";
        let account = Keystore::from(j.to_string()).decrypt("123456").unwrap();
        assert_eq!(account.address.to_string(), "0xd7998FD7F5454722a16Cd67E881CedF9896CE396")
    }

    #[test]
    fn test_decrypt_pbkdf2_password_error() {
        let j = "
        {\"address\":\"0xd7998fd7f5454722a16cd67e881cedf9896ce396\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"cipherparams\":{\"iv\":\"fa9d17a51ba92d61515a6bb629ad842e\"},\"ciphertext\":\"89ad80b27d8325bf79dcef52994e8b4ea626a357120dc8fdca4f0e61058f0496\",\"kdf\":\"pbkdf2\",\"kdfparams\":{\"c\":262144,\"dklen\":32,\"prf\":\"hmac-sha256\",\"salt\":\"dc0b353e69db487ee8ea3716085fe7b6\"},\"mac\":\"e15200e3b57f22714f09629fcf98b79fd8af6f8493c663f09c771e9cb17c1075\"},\"id\":\"83798882-4537-41ae-b205-30b032f2c88d\",\"version\":3}
        ";
        let r = Keystore::from(j.to_string()).decrypt("1234567");
        assert_eq!(r.is_err(), true);
        // 密码错误，KDF 导出错误，故 MAC 错误
        assert_eq!(r.err().unwrap().to_string(), "invalid mac");
    }

    #[test]
    fn test_decrypt_pbkdf2_address_mismatch() {
        let j = "
        {\"address\":\"0x17998fd7f5454722a16cd67e881cedf9896ce396\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"cipherparams\":{\"iv\":\"fa9d17a51ba92d61515a6bb629ad842e\"},\"ciphertext\":\"89ad80b27d8325bf79dcef52994e8b4ea626a357120dc8fdca4f0e61058f0496\",\"kdf\":\"pbkdf2\",\"kdfparams\":{\"c\":262144,\"dklen\":32,\"prf\":\"hmac-sha256\",\"salt\":\"dc0b353e69db487ee8ea3716085fe7b6\"},\"mac\":\"e15200e3b57f22714f09629fcf98b79fd8af6f8493c663f09c771e9cb17c1075\"},\"id\":\"83798882-4537-41ae-b205-30b032f2c88d\",\"version\":3}
        ";
        let r = Keystore::from(j.to_string()).decrypt("123456");
        assert_eq!(r.is_err(), true);
        assert_eq!(r.err().unwrap().to_string(), "address mismatch");
    }

    #[test]
    fn test_decrypt_pbkdf2_invalid_mac() {
        let j = "
        {\"address\":\"0xd7998fd7f5454722a16cd67e881cedf9896ce396\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"cipherparams\":{\"iv\":\"fa9d17a51ba92d61515a6bb629ad842e\"},\"ciphertext\":\"89ad80b27d8325bf79dcef52994e8b4ea626a357120dc8fdca4f0e61058f0496\",\"kdf\":\"pbkdf2\",\"kdfparams\":{\"c\":262144,\"dklen\":32,\"prf\":\"hmac-sha256\",\"salt\":\"dc0b353e69db487ee8ea3716085fe7b6\"},\"mac\":\"e15200e3b57f22714f09629fcf98b79fd8af6f8493c663f09c771e9cb17c1076\"},\"id\":\"83798882-4537-41ae-b205-30b032f2c88d\",\"version\":3}
        ";
        let r = Keystore::from(j.to_string()).decrypt("123456");
        assert_eq!(r.is_err(), true);
        assert_eq!(r.err().unwrap().to_string(), "invalid mac");
    }
}

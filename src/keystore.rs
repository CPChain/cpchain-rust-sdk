use std::fmt::{Display, self};

use cpc_aes::{AESParams, AES, Mode, InitVector};
use pbkdf2::{
    password_hash::{
        rand_core::OsRng, PasswordHasher, SaltString,
    },
    Params, Pbkdf2,
};
use serde::{Deserialize, Serialize, ser::SerializeStruct, de::Visitor};
use uuid::Uuid;
use web3::signing::keccak256;

use crate::accounts::Account;

/// https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
#[derive(Serialize, Deserialize, Debug)]
pub struct Keystore {
    address: String,
    crypto: CryptoInfo,
    id: String,
    version: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct CipherParams {
    iv: String,
}

#[derive(Deserialize, Debug)]
struct CryptoInfo {
    cipher: String,
    cipher_params: CipherParams,
    cipher_text: String,
    kdf: KDF,
    mac: String,
}

impl Serialize for CryptoInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        let mut info = serializer.serialize_struct("CryptoInfo", 1)?;
        info.serialize_field("cipher", &self.cipher)?;
        info.serialize_field("cipherparams", &self.cipher_params)?;
        info.serialize_field("ciphertext", &self.cipher_text)?;
        info.serialize_field("kdf", &self.kdf)?;
        info.serialize_field("kdfparams", &self.kdf.serialize_params().expect("serialize params of kdf failed"))?;
        info.serialize_field("mac", &self.mac)?;
        info.end()
    }
}

// impl <'de> Deserialize <'de> for CryptoInfo {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de> {
//         enum Field {}
//         todo!()
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Pbkdf2Params {
    // 重复计算次数
    c: u64,
    // 期望密钥长度
    dklen: usize,
    // 伪随机函数，如 HMAC
    prf: String,
    // 盐
    salt: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScryptParams {
    dklen: usize,
    n: usize,
    p: usize,
    r: usize,
    salt: String,
}

#[derive(Debug, Clone)]
pub enum KDF {
    PBKDF2(Option<Pbkdf2Params>),
    SCRYPT(Option<ScryptParams>),
}

impl KDF {
    pub fn serialize_params(&self) -> Result<impl Serialize, Box<dyn std::error::Error>> {
        match self {
            KDF::PBKDF2(params) => Ok(serde_json::to_value(&params)?),
            KDF::SCRYPT(params) => Ok(serde_json::to_value(&params)?),
        }
    }
    pub fn encrypt(&self, password: &str) -> Result<(Vec<u8>, KDF), Box<dyn std::error::Error>> {
        match self {
            KDF::PBKDF2(_) => {
                pbkdf2_derive(password)
            },
            KDF::SCRYPT(_) => todo!()
        }
    }
}

impl Serialize for KDF {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
    }
}

impl <'de> Deserialize<'de> for KDF {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        struct StringVisitor;
        impl <'de> Visitor <'de> for StringVisitor {
            type Value = String;
            
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("pbkdf2 or scrypt")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error, {
                Ok(v.to_string())
            }
        }
        let v = deserializer.deserialize_string(StringVisitor)?;
        if v == "pbkdf2" {
            return Ok(KDF::PBKDF2(None))
        }
        return Ok(KDF::SCRYPT(None))
    }
}

impl Display for KDF {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match *self {
            KDF::PBKDF2(_) => "pbkdf2",
            KDF::SCRYPT(_) => "scrypt",
        };
        f.write_str(s)
    }
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

        let decrypted = AES::AES128(derived_key).encrypt(&encrypted, &params).unwrap();

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

fn pbkdf2_derive(password: &str) -> Result<(Vec<u8>, KDF), Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    let rounds = 262144;
    let dklen = 32;
    let params = Params {
        rounds: rounds,
        output_length: dklen,
    };
    let mut salt_bytes: [u8; 16] = [0; 16];
    salt.b64_decode(&mut salt_bytes).unwrap();
    let hash = Pbkdf2
        .hash_password_customized(password.as_bytes(), None, None, params, &salt)
        .expect("PBKDF2 hash failed");
    Ok((hash.hash.unwrap().as_bytes().to_vec(), KDF::PBKDF2(Some(Pbkdf2Params{
        c: rounds as u64,
        dklen: dklen,
        prf: "hmac-sha256".to_string(),
        salt: hex::encode(&salt_bytes),
    }))))
}

#[cfg(test)]
mod tests {
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
    fn test_pbkdf2_derive() {
        let (r, kdf) = pbkdf2_derive("123456").unwrap();
        println!("{}", hex::encode(&r));
        println!("{:?}", kdf);
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

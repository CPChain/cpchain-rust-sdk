use std::fmt::Display;

use serde::{Deserialize, Serialize};

/// https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
#[derive(Serialize, Deserialize, Debug)]
pub struct Keystore<T> {
    address: String,
    crypto: CryptoInfo<T>,
    id: String,
    version: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct CipherParams {
    iv: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CryptoInfo<T> {
    cipher: String,
    #[serde(rename = "cipherparams")]
    cipher_params: CipherParams,
    #[serde(rename = "ciphertext")]
    cipher_text: String,
    kdf: KDF,
    #[serde(rename = "kdfparams")]
    kdf_params: T,
    mac: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Pbkdf2Params {
    c: u64,
    dklen: usize,
    prf: String,
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

#[derive(Deserialize, Debug, Clone)]
pub enum KDF {
    PBKDF2(Pbkdf2Params),
    SCRYPT(ScryptParams),
}

impl Serialize for KDF {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
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

impl <T> Keystore <T> where T: Serialize {
    pub fn to_string(&self) -> Result<String, Box<dyn std::error::Error>> {
        match serde_json::to_string(&self) {
            Ok(s) => return Ok(s),
            Err(e) => return Err(format!("{}", e).into())
        }
    }
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
                kdf: KDF::PBKDF2(pbkdf2_params.clone()),
                kdf_params: pbkdf2_params,
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
                kdf: KDF::SCRYPT(scrypt_params.clone()),
                kdf_params: scrypt_params,
                mac: "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2".to_string(),
            },
            id: "3198bc9c-6672-5ab3-d995-4942343ae5b6".to_string(),
            version: 1,
        };
        let serialized = keystore.to_string().unwrap();
        println!("{}", serialized);
    }
}

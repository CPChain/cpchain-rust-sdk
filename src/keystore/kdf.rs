use std::fmt::{Display, self};

use pbkdf2::{password_hash::{SaltString, PasswordHasher}, Params, Pbkdf2};
use rand_core::OsRng;
use scrypt::{scrypt, Params as ScryptParamsOrigin};
use serde::{Serialize, Deserialize, de::Visitor};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Pbkdf2Params {
    // 重复计算次数
    pub c: u64,
    // 期望密钥长度
    pub dklen: usize,
    // 伪随机函数，如 HMAC-RSA256
    pub prf: String,
    // 盐
    pub salt: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScryptParams {
    pub dklen: usize,
    pub n: usize,
    pub p: u32,
    pub r: u32,
    pub salt: String,
}

#[derive(Debug, Clone)]
pub enum KDF {
    PBKDF2(Option<Pbkdf2Params>),
    /// Ethereum 的 Scrypt 不同于标准 Scrypt https://github.com/ethereum/go-ethereum/issues/19977
    /// https://github.com/golang/crypto/blob/master/scrypt/scrypt.go#L200
    /// http://ricmoo.github.io/scrypt-js/
    /// https://github.com/dchest/scrypt-async-js/blob/master/scrypt-async.js
    /// 标准库的 scrypt 太慢，不适用于区块链常用的 scrypt 参数，故参考 async-scrypt-js，新写一个异步 scrypt
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
            KDF::PBKDF2(params) => {
                pbkdf2_derive(password, params.clone())
            },
            KDF::SCRYPT(_) => {
                todo!()
            }
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

fn rand_salt() -> [u8; 16] {
    let mut salt_bytes: [u8; 16] = [0; 16];
    let salt = SaltString::generate(&mut OsRng);
    salt.b64_decode(&mut salt_bytes).unwrap();
    salt_bytes
}

fn pbkdf2_derive(password: &str, params: Option<Pbkdf2Params>) -> Result<(Vec<u8>, KDF), Box<dyn std::error::Error>> {
    let kdf_params = match params {
        Some(p) => p,
        None => {
            let rounds = 262144;
            let dklen = 32;
            Pbkdf2Params {
                c: rounds as u64,
                dklen: dklen,
                prf: "hmac-sha256".to_string(),
                salt: hex::encode(&rand_salt()),
            }
        }
    };
    let salt = SaltString::b64_encode(&hex::decode(&kdf_params.salt)?);
    if salt.is_err() {
        return Err(format!("Prase salt failed: {}", salt.err().unwrap()).into())
    }
    let salt = salt.unwrap();
    
    let params = Params {
        rounds: kdf_params.c as u32,
        output_length: kdf_params.dklen,
    };
    let hash = Pbkdf2
        .hash_password_customized(password.as_bytes(), None, None, params, &salt)
        .expect("PBKDF2 hash failed");
    Ok((hash.hash.unwrap().as_bytes().to_vec(), KDF::PBKDF2(Some(kdf_params))))
}

fn scrypt_derive(password: &str, params: Option<ScryptParams>) -> Result<(), Box<dyn std::error::Error>> {
    let kdf_params = match params {
        Some(p) => p,
        None => {
            ScryptParams {
                dklen: 32,
                // 参数 n 和 r 决定了占用的内存区域大小和哈希迭代次数
                n: 131072,
                p: 1,
                r: 8,
                salt: hex::encode(&rand_salt()),
            }
        },
    };
    let salt = SaltString::b64_encode(&hex::decode(&kdf_params.salt)?);
    if salt.is_err() {
        return Err(format!("Prase salt failed: {}", salt.err().unwrap()).into())
    }
    // let salt = salt.unwrap();
    // Hash password to PHC string ($scrypt$...)
    let n = (kdf_params.n as f64).log2().ceil();
    if n >= 64.0 {
        return Err("n is too large".into())
    }
    println!("-->{:?}", n);

    let params = ScryptParamsOrigin::new(n as u8, kdf_params.r, kdf_params.p).unwrap();
    let mut output: [u8; 32] = [0; 32];
    scrypt(password.as_bytes(), &hex::decode(&kdf_params.salt)?, &params, &mut output).unwrap();
    println!("{}\n{:?}", kdf_params.salt, hex::encode(output));
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::keystore::kdf::pbkdf2_derive;

    use super::{scrypt_derive, ScryptParams};

    #[test]
    fn test_pbkdf2_derive() {
        let (r, kdf) = pbkdf2_derive("123456", None).unwrap();
        println!("{}", hex::encode(&r));
        println!("{:?}", kdf);
    }

    #[test]
    fn test_scrypt_derive() {
        scrypt_derive("123456", Some(ScryptParams{
            dklen: 32,
            n: 131072,
            p: 1,
            r: 8,
            salt: hex::encode(b"salt"),
        })).unwrap();
    }
}

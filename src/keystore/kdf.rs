use std::fmt::{Display, self};

use pbkdf2::{password_hash::{SaltString, PasswordHasher}, Params, Pbkdf2};
use rand_core::OsRng;
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
    pub p: usize,
    pub r: usize,
    pub salt: String,
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
    use crate::keystore::kdf::pbkdf2_derive;

    #[test]
    fn test_pbkdf2_derive() {
        let (r, kdf) = pbkdf2_derive("123456").unwrap();
        println!("{}", hex::encode(&r));
        println!("{:?}", kdf);
    }
}

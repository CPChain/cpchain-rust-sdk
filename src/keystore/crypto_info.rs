use std::fmt;

use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};

use super::kdf::KDF;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CipherParams {
    pub iv: String,
}

#[derive(Debug, Clone)]
pub struct CryptoInfo {
    pub cipher: String,
    pub cipher_params: CipherParams,
    pub cipher_text: String,
    pub kdf: KDF,
    pub mac: String,
}

impl CryptoInfo {
    fn default() -> CryptoInfo {
        Self {
            cipher: "".to_string(),
            cipher_params: CipherParams { iv: "".to_string() },
            cipher_text: "".to_string(),
            kdf: KDF::PBKDF2(None),
            mac: "".to_string(),
        }
    }
}

impl Serialize for CryptoInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut info = serializer.serialize_struct("CryptoInfo", 1)?;
        info.serialize_field("cipher", &self.cipher)?;
        info.serialize_field("cipherparams", &self.cipher_params)?;
        info.serialize_field("ciphertext", &self.cipher_text)?;
        info.serialize_field("kdf", &self.kdf)?;
        info.serialize_field(
            "kdfparams",
            &self
                .kdf
                .serialize_params()
                .expect("serialize params of kdf failed"),
        )?;
        info.serialize_field("mac", &self.mac)?;
        info.end()
    }
}

impl<'de> Deserialize<'de> for CryptoInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        enum Field {
            Cipher,
            CipherParams,
            CipherText,
            KDF,
            Mac,
            KdfParams,
        }
        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`secs` or `nanos`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "cipher" => Ok(Field::Cipher),
                            "cipherparams" => Ok(Field::CipherParams),
                            "ciphertext" => Ok(Field::CipherText),
                            "kdf" => Ok(Field::KDF),
                            "mac" => Ok(Field::Mac),
                            "kdfparams" => Ok(Field::KdfParams),
                            _ => Err(de::Error::unknown_field(value, &FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        // Struct
        struct CryptoInfoVisitor;

        impl<'de> Visitor<'de> for CryptoInfoVisitor {
            type Value = CryptoInfo;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct CryptoInfo")
            }

            fn visit_map<V>(self, mut map: V) -> Result<CryptoInfo, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut cipher = None;
                let mut cipher_params = None;
                let mut cipher_text = None;
                let mut kdf = None;
                let mut kdf_params_data: Option<KDF> = None;
                // let mut kdf_params_scrypt = None;
                // let mut kdf_params_pbkdf2 = None;
                let mut mac = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Cipher => {
                            if cipher.is_some() {
                                return Err(de::Error::duplicate_field("cipher"));
                            }
                            cipher = Some(map.next_value()?);
                        }
                        Field::CipherParams => {
                            if cipher_params.is_some() {
                                return Err(de::Error::duplicate_field("cipherparams"));
                            }
                            cipher_params = Some(map.next_value()?);
                        }
                        Field::CipherText => {
                            if cipher_text.is_some() {
                                return Err(de::Error::duplicate_field("ciphertext"));
                            }
                            cipher_text = Some(map.next_value()?);
                        }
                        Field::KDF => {
                            if kdf.is_some() {
                                return Err(de::Error::duplicate_field("kdf"));
                            }
                            kdf = Some(map.next_value()?);
                        }
                        Field::Mac => {
                            if mac.is_some() {
                                return Err(de::Error::duplicate_field("mac"));
                            }
                            mac = Some(map.next_value()?);
                        }
                        Field::KdfParams => {
                            if kdf_params_data.is_some() {
                                return Err(de::Error::duplicate_field("kdfparams"));
                            }
                            kdf_params_data = Some(map.next_value()?);
                        }
                    }
                }
                let cipher = cipher.ok_or_else(|| de::Error::missing_field("cipher"))?;
                let cipher_params =
                    cipher_params.ok_or_else(|| de::Error::missing_field("cipherparams"))?;
                let cipher_text =
                    cipher_text.ok_or_else(|| de::Error::missing_field("ciphertext"))?;
                let mac = mac.ok_or_else(|| de::Error::missing_field("mac"))?;
                // 获取 KDF
                let real_kdf = kdf_params_data.clone();
                let kdf: String = kdf.ok_or_else(|| de::Error::missing_field("kdf"))?;

                if kdf != "scrypt" && kdf != "pbkdf2" {
                    return Err(de::Error::custom("Unknown KDF algorithm"));
                }

                let mut crypto = CryptoInfo::default();
                crypto.cipher = cipher;
                crypto.cipher_params = cipher_params;
                crypto.cipher_text = cipher_text;
                crypto.kdf = real_kdf.unwrap();
                crypto.mac = mac;
                Ok(crypto)
            }
        }
        const FIELDS: &'static [&'static str] = &[
            "cipher",
            "cipherparams",
            "ciphertext",
            "kdf",
            "kdfparams",
            "mac",
        ];
        deserializer.deserialize_struct("Duration", FIELDS, CryptoInfoVisitor)
    }
}

impl From<String> for CryptoInfo {
    fn from(s: String) -> Self {
        serde_json::from_str(s.as_str()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::keystore::crypto_info::CryptoInfo;

    #[test]
    fn test_deserialize() {
        let j = "
            {\"cipher\":\"aes-128-ctr\",\"cipherparams\":{\"iv\":\"24242424242424242424242424242424\"},\"ciphertext\":\"9a4785cd9c59ac3550e7be9c47045e24ae93bcd85518dd510f0e83537a6b1cf7\",\"kdf\":\"pbkdf2\",\"kdfparams\":{\"c\":262144,\"dklen\":32,\"prf\":\"hmac-sha256\",\"salt\":\"6949646d3976356e2b636e74462b32476d3742465677\"},\"mac\":\"1da9056f139ee205cc342233a1bfc3fb7cbd9f4d904aa9b971e373c369aee840\"}
        ";
        let ks = CryptoInfo::from(j.to_string());
        println!("{:?}", ks);
    }
}

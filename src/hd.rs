use bip39::{Language, Mnemonic, MnemonicType, Seed};
use hex_literal::hex;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use regex::Regex;
use secp256k1::{ecdsa, PublicKey, Secp256k1, SecretKey};
use sha2::Sha512;

// "Bitcoin seed"
const MASTER_SECRET: &str = "Bitcoin seed";

/// HMAC: Keyed-Hashing for Message Authentication
type HmacSha512 = Hmac<Sha512>;

// 正常衍生的索引号范围为 [0x0, 0x7FFFFFFF]，而硬化衍生的索引号范围为 [0x80000000, 0xFFFFFFFF]
const HARDENED_BIT: u64 = 0x80000000;

/// Deterministic Wallet
/// BIP39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
/// https://stevenocean.github.io/2018/09/23/generate-hd-wallet-by-bip39.html
#[derive(Debug, Clone)]
struct HDNode {
    pub private_key: Option<[u8; 32]>,
    pub public_key: [u8; 33], // beginning with 0x02 or 0x03 to denote the sign of the missing Y component.
    address: String,

    pub mnemonic: Option<Mnemonic>,
    pub path: String,

    chain_code: [u8; 32],

    pub index: u64,
    pub depth: u32,
}

impl HDNode {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // 创建助记词
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        // Create seed
        let seed = Seed::new(&mnemonic, "");
        let bytes = compute_hmac(MASTER_SECRET.as_bytes(), &seed.as_bytes())?;
        let mut master_private_key: [u8; 32] = [0; 32];
        bytes[0..32]
            .to_vec()
            .iter()
            .enumerate()
            .for_each(|(index, elem)| {
                master_private_key[index] = elem.clone();
            });
        let secp = Secp256k1::new();
        // Get public key
        let secret_key = SecretKey::from_slice(&master_private_key)?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let public_key: [u8; 33] = public_key.serialize();

        let mut master_chain_code: [u8; 32] = [0; 32];
        bytes[32..64]
            .to_vec()
            .iter()
            .enumerate()
            .for_each(|(index, elem)| {
                master_chain_code[index] = elem.clone();
            });
        Ok(HDNode::new_hdnode(
            Some(master_private_key),
            public_key,
            master_chain_code,
            0,
            0,
            "".to_string(),
            Some(mnemonic),
        ))
    }

    fn new_hdnode(
        private_key: Option<[u8; 32]>,
        public_key: [u8; 33],
        chain_code: [u8; 32],
        index: u64,
        depth: u32,
        path: String,
        mnemonic: Option<Mnemonic>,
    ) -> Self {
        Self {
            private_key,
            public_key,
            chain_code,
            index,
            depth,
            address: String::new(),
            mnemonic,
            path,
        }
    }
    fn _derive(&self, index: u64) -> Result<HDNode, Box<dyn std::error::Error>> {
        if index > 0xffffffff {
            return Err(format!("invalid index - {}", index).into());
        }

        // Base path
        let mut path = self.path.clone();
        if path.len() > 0 {
            path += &format!("/{}", (index & !HARDENED_BIT))
        }

        let mut data: [u8; 37] = [0; 37];

        if (index & HARDENED_BIT) > 0 {
            match &self.private_key {
                Some(pk) => {
                    // Data = 0x00 || ser_256(k_par)
                    pk.iter().enumerate().for_each(|(index, e)| {
                        data[index + 1] = e.clone();
                    });
                    // Hardened path
                    if path.len() > 0 {
                        path += "'";
                    }
                }
                None => return Err("cannot derive child of neutered node".into()),
            }
        } else {
            // Data = ser_p(point(k_par))
            self.public_key.iter().enumerate().for_each(|(index, e)| {
                data[index] = *e;
            });
        }

        // Data += ser_32(i)
        let mut i: i32 = 24;
        while i >= 0 {
            data[(33 + (i >> 3)) as usize] = ((index >> (24 - i)) & 0xff) as u8;
            i -= 8;
        }

        let hmac_result = compute_hmac(&self.chain_code, &data)?;
        let hmac_result_left: &[u8; 32] = &hmac_result[..32].try_into().unwrap();
        let child_chain_code: &[u8; 32] = &hmac_result[32..].try_into().unwrap();

        let secp = Secp256k1::new();

        // 私钥
        let (private_key, public_key): ([u8; 32], [u8; 33]) = match self.private_key {
            Some(pk) => {
                let bn1 = BigUint::from_bytes_be(&pk);
                let bn2 = BigUint::from_bytes_be(hmac_result_left);
                let r = (bn1 + bn2)
                    % BigUint::from_bytes_be(&hex!(
                        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
                    ));
                let mut ki: [u8; 32] = [0; 32];
                r.to_bytes_le()[..32]
                    .iter()
                    .enumerate()
                    .for_each(|(index, e)| {
                        ki[index] = e.clone();
                    });
                let secret_key = SecretKey::from_slice(&ki)?;
                let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                let public_key: [u8; 33] = public_key.serialize();
                (ki, public_key)
            }
            None => {
                // let ki = hmac_result_left.clone();
                // let secret_key = SecretKey::from_slice(&ki)?;
                // let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                // // elliptic_curve::PublicKey::from_slice(&public_key);
                // elliptic_curve::
                // ki
                todo!()
            }
        };

        let node = HDNode::new_hdnode(
            Some(private_key),
            public_key,
            child_chain_code.clone(),
            index,
            self.depth + 1,
            path,
            self.mnemonic.clone(),
        );
        Ok(node)
    }

    fn derive_path(&self, path: &str) -> Result<HDNode, Box<dyn std::error::Error>> {
        let mut components = path.split("/").collect::<Vec<_>>();
        if components.len() == 0 || (components[0] == "m" && self.depth != 0) {
            return Err(format!("invalid path - {}", path).into());
        }

        if components[0] == "m" {
            components = components[1..components.len()].to_vec();
        }
        let r1 = Regex::new(r"^\d+'$")?;
        let r2 = Regex::new(r"^\d+$")?;
        let mut node = self.clone();
        for elem in components.iter() {
            if r1.is_match(elem) {
                let index = elem[..elem.len() - 1].to_string().parse::<u64>()?;
                if index > HARDENED_BIT {
                    return Err(format!("invalid path index - {}", index).into());
                }
                node = self._derive(HARDENED_BIT + index)?;
            } else if r2.is_match(elem) {
                let index = elem.to_string().parse::<u64>()?;
                if index > HARDENED_BIT {
                    return Err(format!("invalid path index - {}", index).into());
                }
                node = self._derive(index)?;
            }
        }
        Ok(node)
    }
}

fn compute_hmac(key: &[u8], message: &[u8]) -> Result<[u8; 64], Box<dyn std::error::Error>> {
    let mut mac = HmacSha512::new_from_slice(key)?;
    mac.update(message);
    let result = mac.finalize();
    let code_bytes: [u8; 64] = result.into_bytes().into();
    Ok(code_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_hd() {
        let a = HDNode::new().unwrap();
        let node = a.derive_path("m/44'/337'/0'/0/0").unwrap();
        let pk = hex::encode(&node.private_key.unwrap());
        println!("{}", node.mnemonic.unwrap().phrase());
        println!("{}", pk)
    }

    #[test]
    fn test_hmac() {
        // hmac online: https://1024tools.com/hmac
        let mut mac = HmacSha512::new_from_slice(b"my secret and secure key")
            .expect("HMAC can take key of any size");
        mac.update(b"input message");
        let result = mac.finalize();
        // To get underlying array use `into_bytes`, but be careful, since
        // incorrect use of the code value may permit timing attacks which defeats
        // the security provided by the `CtOutput`
        let code_bytes = result.into_bytes();
        let expected = hex!(
            "
            e51c913d44379e50c69201a5d95fb43ec0d
            c5b1736cd6f2214b506e64bd35c9dc0214c
            900f62be4b61d507a60299b6bb1625e5e36
            5a9aa4ed1089b0262fb99a5
        "
        );
        assert_eq!(code_bytes[..], expected[..]);
    }

    #[test]
    fn test_compute_hmac() {
        let code_bytes = compute_hmac(b"my secret and secure key", b"input message").unwrap();
        let expected = hex!(
            "
            e51c913d44379e50c69201a5d95fb43ec0d
            c5b1736cd6f2214b506e64bd35c9dc0214c
            900f62be4b61d507a60299b6bb1625e5e36
            5a9aa4ed1089b0262fb99a5
        "
        );
        assert_eq!(code_bytes[..], expected[..]);
    }
}

pub use common::*;
use my_ctr::aes_ctr;
use ecb::{encrypt_ebc, decrypt_ebc};
use sha2::{Sha256, Digest};
mod ecb;
mod my_ctr;
mod common;

pub enum AES {
	AES128([u8; 16]),
	AES256([u8; 32]),
}

impl AES {
	pub fn encrypt(&self, data: &Vec<u8>, params: &AESParams) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
		match *self {
			AES::AES256(key) => match params.mode.as_ref().unwrap_or(&Mode::CTR(InitVector::I16([0x24; 16]))) {
				Mode::ECB => {
					Ok(encrypt_ebc(key, &data))
				}
    			Mode::CTR(_) => todo!(),
			}
			AES::AES128(key) => match params.mode.as_ref().unwrap_or(&Mode::CTR(InitVector::I16([0x24; 16]))) {
				Mode::ECB => todo!(),
				Mode::CTR(iv) => {
					Ok(aes_ctr(key, data.clone(), Some(iv.iv())))
				},
			},
		}
	}
	pub fn decrypt(&self, encrypted_data: &Vec<u8>, params: &AESParams) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
		match *self {
			AES::AES256(key) => match params.mode.as_ref().unwrap_or(&Mode::CTR(InitVector::I16([0x24; 16]))) {
				Mode::ECB => {
					Ok(decrypt_ebc(key, encrypted_data))
				},
				Mode::CTR(_) => todo!(),
			}
    		AES::AES128(key) => match params.mode.as_ref().unwrap_or(&Mode::CTR(InitVector::I16([0x24; 16]))) {
				Mode::ECB => todo!(),
				Mode::CTR(iv) => {
					Ok(aes_ctr(key, encrypted_data.clone(), Some(iv.iv())))
				},
			},
		}
	}
}

// Generate 32 bytes (256 bit) secret
pub fn aes256_kdf(password: &String) -> Result<[u8; 32], Box<dyn std::error::Error>> {
	// create a Sha256 object
	let mut hasher = Sha256::new();

	// write input message
	hasher.update(password.as_bytes());

	// read hash digest and consume hasher
	let result = hasher.finalize();
	let mut key: [u8;32] = [0;32];
	for i in 0..result.len() {
		key[i] = result[i];
	}
	Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
	use hex_literal::hex as hex_macro;

	#[test]
	fn test_aes_ecd() {
		let pwd = "password".to_string();
		let key = aes256_kdf(&pwd).unwrap();
		let data = "cpchaincpchaincpchaincpchaincpchaincpchaincpchaincpchain";
		let params = AESParams {
			mode: Some(Mode::ECB)
		};
		let encryted = AES::AES256(key).encrypt(&data.as_bytes().to_vec(), &params).unwrap();
		// Encrypted by http://aes.online-domain-tools.com/
		let expected = hex_macro!("836c568e9aa0df25e569d486a7d4ecf26263745c6438a160beb7cf5f4b1f9b36b79bbd20f477efe727cea7eacbba11598698001a8ecc55324078f121a14a6d3b");
		assert_eq!(encryted, expected);
		let decrypted = AES::AES256(key).decrypt(&encryted.clone(), &params).unwrap();
		assert_eq!(decrypted, hex_macro!("6370636861696e6370636861696e6370636861696e6370636861696e6370636861696e6370636861696e6370636861696e6370636861696e"));
	}

	#[test]
	fn test_cpc_ctr() {
		let key = [0x42; 16];
		let iv = [0x24; 16];
		// let iv = [0x24; 16];
		let plaintext = *b"hello world! this is my plaintext.";
		let ciphertext = hex_macro!(
			"3357121ebb5a29468bd861467596ce3da59bdee42dcc0614dea955368d8a5dc0cad4"
		);
		let params = AESParams {
			mode: Some(Mode::CTR(InitVector::I16(iv)))
		};
		let encrypted = AES::AES128(key).encrypt(&plaintext.to_vec(), &params).unwrap();
		assert_eq!(encrypted[..], ciphertext[..]);
		let decrypted = AES::AES128(key).decrypt(&encrypted, &params).unwrap();
		assert_eq!(decrypted[..], plaintext[..]);
		println!("{}", String::from_utf8(decrypted).unwrap())
	}
}

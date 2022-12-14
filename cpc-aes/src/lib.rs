use aes::Aes256;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use sha2::{Sha256, Digest};

const AES_BLOCK_SIZE: usize = 16;

/// http://aes.online-domain-tools.com/
pub enum AES {
	AES256
}

pub fn encrypt(key: [u8;32], data: Vec<u8>) -> Vec<u8> {
	let key = GenericArray::from(key);
	// Initialize cipher
	let cipher = Aes256::new(&key);
	// Encrypt
	let mut i = 0;
	let mut result: Vec<u8> = Vec::new();
	loop {
		let mut buffer = [0u8;AES_BLOCK_SIZE];
		for j in 0..AES_BLOCK_SIZE {
			if (i + j) >= data.len() {
				break;
			}
			buffer[j] = data[i + j];
		}
		let mut block = GenericArray::from(buffer);
		cipher.encrypt_block(&mut block);
		i += AES_BLOCK_SIZE;
		result.append(&mut block.to_vec());
		if i >= data.len() {
			break;
		}
	}
	result
}

pub fn decrypt(key: [u8; 32], data: Vec<u8>) -> Vec<u8> {
	let key = GenericArray::from(key);
	// Initialize cipher
	let cipher = Aes256::new(&key);
	// Encrypt
	let mut i = 0;
	let mut result: Vec<u8> = Vec::new();
	loop {
		let mut buffer = [0u8;AES_BLOCK_SIZE];
		for j in 0..AES_BLOCK_SIZE {
			if (i + j) >= data.len() {
				break;
			}
			buffer[j] = data[i + j];
		}
		let mut block = GenericArray::from(buffer);
		cipher.decrypt_block(&mut block);
		i += AES_BLOCK_SIZE;
		if i >= data.len() {
			let r = &mut block.to_vec();
			while r.len() > 0 && r[r.len() - 1] == 0 {
				r.pop();
			}
			result.append(r);
			break;
		} else {
			result.append(&mut block.to_vec());
		}
	}
	result
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
	fn test_aes() {
		let pwd = "password".to_string();
		let key = aes256_kdf(&pwd).unwrap();
		println!("{}", hex::encode(&key[..32]));
		let data = "cpchaincpchaincpchaincpchaincpchaincpchaincpchaincpchain";
		println!("Data: {:x?}", data.as_bytes());
		let encryted = encrypt(key, data.as_bytes().to_vec());
		// Encrypted by http://aes.online-domain-tools.com/
		let expected = hex_macro!("836c568e9aa0df25e569d486a7d4ecf26263745c6438a160beb7cf5f4b1f9b36b79bbd20f477efe727cea7eacbba11598698001a8ecc55324078f121a14a6d3b");
		assert_eq!(encryted, expected);
		println!("Encrypted data: {:x?}", encryted.as_slice());
		let decrypted = decrypt(key, encryted.clone());
		println!("Decrypted data: {:x?}", decrypted.as_slice());
	}
}

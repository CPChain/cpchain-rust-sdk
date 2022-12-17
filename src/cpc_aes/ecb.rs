
use aes::{cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
}, Aes256};

const AES_BLOCK_SIZE: usize = 16;

pub fn encrypt_ebc(key: [u8;32], data: &Vec<u8>) -> Vec<u8> {
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

pub fn decrypt_ebc(key: [u8; 32], data: &Vec<u8>) -> Vec<u8> {
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

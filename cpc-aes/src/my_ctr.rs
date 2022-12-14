
use aes::cipher::{KeyIvInit, StreamCipher};
use ctr;

type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

pub fn aes_ctr(key: [u8; 16], mut data: Vec<u8>, iv: Option<[u8; 16]>) -> Vec<u8> {
	let iv = iv.unwrap_or([0x24; 16]);
	let mut cipher = Aes128Ctr64LE::new(&key.into(), &iv.into());
	cipher.apply_keystream(&mut data);
	data
}

#[cfg(test)]
mod tests {
    use super::aes_ctr;
	use hex_literal::hex;

	#[test]
	fn test_ctr() {
		let key = [0x42; 16];
		let iv = [0x24; 16];
		// let iv = [0x24; 16];
		let plaintext = *b"hello world! this is my plaintext.";
		let ciphertext = hex!(
			"3357121ebb5a29468bd861467596ce3da59bdee42dcc0614dea955368d8a5dc0cad4"
		);
		let encrypted = aes_ctr(key, plaintext.to_vec(), Some(iv));
		assert_eq!(encrypted[..], ciphertext[..]);
		let decrypted = aes_ctr(key, encrypted, Some(iv));
		assert_eq!(decrypted[..], plaintext[..]);
		println!("{}", String::from_utf8(decrypted).unwrap())
	}
}

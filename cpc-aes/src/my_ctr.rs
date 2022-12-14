
use aes::cipher::{KeyIvInit, StreamCipher};
use ctr;

type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;

pub fn aes_ctr(key: [u8; 16], mut data: Vec<u8>, iv: Option<[u8; 16]>) -> Vec<u8> {
	let iv = iv.unwrap_or([0x24; 16]);
	let mut cipher = Aes128Ctr64BE::new(&key.into(), &iv.into());
	cipher.apply_keystream(&mut data);
	data
}

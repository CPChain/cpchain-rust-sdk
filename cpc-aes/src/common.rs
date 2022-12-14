pub enum InitVector {
	I16([u8; 16])
}

impl InitVector {
    // TODO 实现泛型，或者宏
    pub fn iv(&self) -> [u8; 16] {
        match *self {
            InitVector::I16(iv) => iv,
        }
    }
}

pub enum Mode {
	// Electronic Block Encrypt
	ECB,
	// Counter mode encryption
	CTR(InitVector)
}

pub struct AESParams {
	pub mode: Option<Mode>,
}

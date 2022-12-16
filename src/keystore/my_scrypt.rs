use hmac::Hmac;
use sha2::Sha256;

use super::bits;

/// https://github.com/golang/crypto/blob/master/scrypt/scrypt.go
/// TODO 搞清楚为什么 Go 实现的 Scrypt 比 Rust 的快这么多

fn as_u32_be(array: &[u8]) -> u32 {
    ((array[0] as u32) << 24) +
    ((array[1] as u32) << 16) +
    ((array[2] as u32) <<  8) +
    ((array[3] as u32) <<  0)
}

fn as_u32_le(array: &[u8]) -> u32 {
    ((array[0] as u32) <<  0) +
    ((array[1] as u32) <<  8) +
    ((array[2] as u32) << 16) +
    ((array[3] as u32) << 24)
}

// blockCopy copies n numbers from src into dst.
fn blockCopy(dst: &mut [u32], src: &[u32], n: usize) {
	// copy(dst, src[:n])
    src[..n].iter().enumerate().for_each(|(index, b)|{
        dst[index] = *b;
    });
}

// blockXOR XORs numbers from dst with n numbers from src.
fn blockXOR(dst: &mut [u32], src: &[u32], n: usize) {
	src[..n].iter().enumerate().for_each(|(index, b)| {
        dst[index] ^= *b
    });
}

fn blockMix(tmp: &mut [u32; 16], input: &[u32], out: &mut [u32], r: usize) {
    blockCopy(tmp, &input[(2*r-1)*16..], 16);
    let mut i = 0;
    while i < 2*r {
        let tmp_out = salsaXOR(tmp, &input[((i*16) as usize)..]);
        tmp_out.iter().enumerate().for_each(|(index, b)| {
            out[(i*8 + index) as usize] = *b;
        });
        let tmp_out = salsaXOR(tmp, &input[((i*16+16) as usize)..]);
        tmp_out.iter().enumerate().for_each(|(index, b)| {
            out[((i*8+r*16) as usize + index)] = *b;
        });
        i+=2;
    }
}

fn add(a: u32, b: u32) -> u32 {
    // 支持整型溢出
    ((a as u64) + (b as u64)) as u32
}

// salsaXOR applies Salsa20/8 to the XOR of 16 numbers from tmp and in,
// and puts the result into both tmp and out.
fn salsaXOR(tmp: &mut [u32; 16], input: &[u32]) -> [u32; 16] {
    let w0 = tmp[0] ^ input[0];
	let w1 = tmp[1] ^ input[1];
	let w2 = tmp[2] ^ input[2];
	let w3 = tmp[3] ^ input[3];
	let w4 = tmp[4] ^ input[4];
	let w5 = tmp[5] ^ input[5];
	let w6 = tmp[6] ^ input[6];
	let w7 = tmp[7] ^ input[7];
	let w8 = tmp[8] ^ input[8];
	let w9 = tmp[9] ^ input[9];
	let w10 = tmp[10] ^ input[10];
	let w11 = tmp[11] ^ input[11];
	let w12 = tmp[12] ^ input[12];
	let w13 = tmp[13] ^ input[13];
	let w14 = tmp[14] ^ input[14];
	let w15 = tmp[15] ^ input[15];

	let mut x0 = w0;
    let mut x1 = w1;
    let mut x2 = w2;
    let mut x3 = w3;
    let mut x4 = w4;
    let mut x5 = w5;
    let mut x6 = w6;
    let mut x7 = w7;
    let mut x8 = w8;
    let mut x9 = w9;
    let mut x10 = w10;
    let mut x11 = w11;
    let mut x12 = w12;
    let mut x13 = w13;
    let mut x14 = w14;
    let mut x15 = w15;

    let mut i = 0;
    while i < 8 {
		x4 ^= bits::rotate_left32(add(x0, x12), 7);
		x8 ^= bits::rotate_left32(add(x4, x0), 9);
		x12 ^= bits::rotate_left32(add(x8, x4), 13);
		x0 ^= bits::rotate_left32(add(x12, x8), 18);

		x9 ^= bits::rotate_left32(add(x5, x1), 7);
		x13 ^= bits::rotate_left32(add(x9, x5), 9);
		x1 ^= bits::rotate_left32(add(x13, x9), 13);
		x5 ^= bits::rotate_left32(add(x1, x13), 18);

		x14 ^= bits::rotate_left32(add(x10, x6), 7);
		x2 ^= bits::rotate_left32(add(x14, x10), 9);
		x6 ^= bits::rotate_left32(add(x2, x14), 13);
		x10 ^= bits::rotate_left32(add(x6, x2), 18);

		x3 ^= bits::rotate_left32(add(x15, x11), 7);
		x7 ^= bits::rotate_left32(add(x3, x15), 9);
		x11 ^= bits::rotate_left32(add(x7, x3), 13);
		x15 ^= bits::rotate_left32(add(x11, x7), 18);

		x1 ^= bits::rotate_left32(add(x0, x3), 7);
		x2 ^= bits::rotate_left32(add(x1, x0), 9);
		x3 ^= bits::rotate_left32(add(x2, x1), 13);
		x0 ^= bits::rotate_left32(add(x3, x2), 18);

		x6 ^= bits::rotate_left32(add(x5, x4), 7);
		x7 ^= bits::rotate_left32(add(x6, x5), 9);
		x4 ^= bits::rotate_left32(add(x7, x6), 13);
		x5 ^= bits::rotate_left32(add(x4, x7), 18);

		x11 ^= bits::rotate_left32(add(x10, x9), 7);
		x8 ^= bits::rotate_left32(add(x11, x10), 9);
		x9 ^= bits::rotate_left32(add(x8, x11), 13);
		x10 ^= bits::rotate_left32(add(x9, x8), 18);

		x12 ^= bits::rotate_left32(add(x15, x14), 7);
		x13 ^= bits::rotate_left32(add(x12, x15), 9);
		x14 ^= bits::rotate_left32(add(x13, x12), 13);
		x15 ^= bits::rotate_left32(add(x14, x13), 18);
        i += 2;
	}
	x0 = add(x0, w0);
	x1 = add(x1, w1);
	x2 = add(x2, w2);
	x3 = add(x3, w3);
	x4 = add(x4, w4);
	x5 = add(x5, w5);
	x6 = add(x6, w6);
	x7 = add(x7, w7);
	x8 = add(x8, w8);
	x9 = add(x9, w9);
	x10 = add(x10, w10);
	x11 = add(x11, w11);
	x12 = add(x12, w12);
	x13 = add(x13, w13);
	x14 = add(x14, w14);
	x15 = add(x15, w15);

    let x: [u32; 16] = [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15];
    let mut out:[u32; 16] = [0; 16];
    x.iter().enumerate().for_each(|(index, b)| {
        out[index] = *b;
        tmp[index] = *b;
    });
    return out
}

fn integer(b: &[u32], r: u32) -> u64 {
	let j = (2*r - 1) * 16;
	return b[j as usize] as u64 | (b[(j+1) as usize] as u64)<<32
}

fn transform_u32_to_array_of_u8(x:u32) -> [u8;4] {
    let b1 : u8 = ((x >> 24) & 0xff) as u8;
    let b2 : u8 = ((x >> 16) & 0xff) as u8;
    let b3 : u8 = ((x >> 8) & 0xff) as u8;
    let b4 : u8 = (x & 0xff) as u8;
    return [b4, b3, b2, b1]
}

fn smix(b: &mut [u8], r: u32, N: u32, v: &mut [u32], xy: &mut [u32]) {
    let mut tmp: [u32; 16] = [0; 16];
	let R = 32 * r;
	let x = xy;
	let mut y = x[(R as usize)..].to_vec();

	let mut j = 0;
    let mut i: usize = 0;

	while i < (R as usize) {
        let t = as_u32_le(&b[j..j+4]);
        x[i] = t;
		j += 4;
        i += 1;
	}
    let mut i = 0;
    println!("-->1 {} {} {} {} {}", x.len(), x[0], x[511], i, N);
	while i < N {
        blockCopy(&mut (v[((i*R) as usize)..]), x, R as usize);
		blockMix(&mut tmp, x, &mut y, r as usize);
        // 修改 y 后，要立刻覆盖 x
        blockCopy(&mut x[(R as usize)..], &y, y.len());
        
		blockCopy(&mut (v[(((i+1)*R) as usize)..]), &y, R as usize);
		blockMix(&mut tmp, &y, x, r as usize);
        i += 2;
	}
    println!("-->2 {} {} {}", y.len(), y[0], y[255]);
    let mut i = 0;
    let mut j: i32;
	while i < N {
		j = (integer(x, r) & ((N-1) as u64)) as i32;
        blockXOR(x, &v[(((j as u32) * R) as usize)..], R as usize);
		blockMix(&mut tmp, x, &mut y, r as usize);
        // 修改 y 后，要立刻覆盖 x
        blockCopy(&mut x[(R as usize)..], &y, y.len());

		j = (integer(&mut y, r) & (N-1) as u64) as i32;
		blockXOR(&mut y, &mut v[(((j as u32)*R) as usize)..], R as usize);
        // 修改 y 后，要立刻覆盖 x
        blockCopy(&mut x[(R as usize)..], &y, y.len());
		blockMix(&mut tmp, &y, x, r as usize);
        i += 2;
	}
    println!("-->3 {} {} {}", x.len(), x[0], x[511]);
	let mut j: usize = 0;
	for v in &x[..(R as usize)] {
        println!("{}", v);
        transform_u32_to_array_of_u8(*v).iter().enumerate().for_each(|(i, v)| {
            b[j + i] = *v; 
        });
		j += 4;
	}
    println!("-->4 {} {} {}", b.len(), b[0], b[1023])
}

fn create_arr<T>(n: u32) -> Vec<T> where T: Default  {
    let mut v = Vec::<T>::with_capacity(n.try_into().unwrap());
    for _ in 0..n {
        v.push(T::default());
    }
    v
}

pub fn scrypt(password: &str, salt: &[u8], N: u32, r: u32, p: u32, dklen: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if N <= 1 || N&(N-1) != 0 {
		return Err("scrypt: N must be > 1 and a power of 2".into())
	}
	// if (r as u64)* (p as u64) >= 1<<30 || r > maxInt/128/p || r > maxInt/256 || N > maxInt/128/r {
	// 	return nil, errors.New("scrypt: parameters are too large")
	// }

    let mut xy = create_arr::<u32>(64 * r);
    let mut v = create_arr::<u32>(32 * N * r);

    let mut b = create_arr::<u8>(p*128*r);
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, 1, &mut b);

    for i in 0..p {
        let index = (i * 128 * r) as usize;
		smix(&mut b[index..], r, N, &mut v, &mut xy);
	}

    let mut result = create_arr::<u8>(dklen);

    // println!("{:?}", hex::encode(&b));

    pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &b, 1, &mut result);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::scrypt;

    #[test]
    fn test_scrypt() {
        let derived = scrypt("123456", b"salt", 262144, 8, 1, 32).unwrap();
        println!("{}", hex::encode(derived));
    }
}

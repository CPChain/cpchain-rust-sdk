
/// rotate_left32 returns the value of x rotated left by (k mod 32) bits.
/// To rotate x right by k bits, call RotateLeft32(x, -k).
///
/// This function's execution time does not depend on the inputs.
pub fn rotate_left32(x: u32, k: i32) -> u32 {
	let n = 32;
	let s = (k as u32) & (n - 1);
	return x<<s | x>>(n-s)
}

#[cfg(test)]
mod tests {
    use super::rotate_left32;

    #[test]
    fn test_bits() {
        assert_eq!(rotate_left32(0x10, 7), 2048);
        assert_eq!(rotate_left32(0x10, -3), 2);
        rotate_left32(0x10000000, 18);
        let a: u32 = 4264765846;
        let b: u32 = 435110852;
        let c = ((a as u64) + (b as u64)) as u32;
        println!("{}", c)
    }
}

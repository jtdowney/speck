use speck::*;

fn main() {
    let cipher = Speck64_128::new([0, 1, 3, 4]);

    for id in (1..).take(1000) {
	let encrypted_id = encrypt_id(&cipher, id);
	let decrypted_id = decrypt_id(&cipher, encrypted_id);
	println!("{id} -> {encrypted_id} -> {decrypted_id}");
    }
}

fn encrypt_id(cipher: &Speck64_128, id: u64) -> u64 {
    let mut data = id.to_le_bytes();
    cipher.seal_in_place(&mut data).unwrap();
    u64::from_le_bytes(data)
}

fn decrypt_id(cipher: &Speck64_128, id: u64) -> u64 {
    let mut data = id.to_le_bytes();
    cipher.open_in_place(&mut data).unwrap();
    u64::from_le_bytes(data)
}

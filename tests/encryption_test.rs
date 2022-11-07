use getrandom::getrandom;
use speck::{Speck128_128, SpeckCipher};

#[test]
fn test_round_trip() {
    let mut key = [0; 16];
    getrandom(&mut key).unwrap();

    let mut input = [0; 16];
    getrandom(&mut input).unwrap();

    let mut buffer = input.clone();
    let cipher = Speck128_128::new_slice(&key).unwrap();

    cipher.seal_in_place(&mut buffer).unwrap();
    assert_ne!(input, buffer);

    cipher.open_in_place(&mut buffer).unwrap();
    assert_eq!(input, buffer);
}

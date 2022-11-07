use serde::Deserialize;
use speck::{self, Speck128_128, Speck128_192, Speck128_256, Speck64_128, Speck64_96, SpeckCipher};

const VECTORS: &str = include_str!("vectors.toml");

#[derive(Debug, Deserialize)]
struct Data {
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    key: String,
    plaintext: String,
    ciphertext: String,
}

fn create_cipher(vector: &Vector) -> Box<dyn SpeckCipher> {
    match vector.name.as_str() {
        "SPECK-64/96" => {
            let key_data = hex::decode(&vector.key).unwrap();
            let key = key_data.as_slice().try_into().unwrap();
            Box::new(Speck64_96::new_slice(key).unwrap())
        }
        "SPECK-64/128" => {
            let key_data = hex::decode(&vector.key).unwrap();
            let key = key_data.as_slice().try_into().unwrap();
            Box::new(Speck64_128::new_slice(key).unwrap())
        }
        "SPECK-128/128" => {
            let key_data = hex::decode(&vector.key).unwrap();
            let key = key_data.as_slice().try_into().unwrap();
            Box::new(Speck128_128::new_slice(key).unwrap())
        }
        "SPECK-128/192" => {
            let key_data = hex::decode(&vector.key).unwrap();
            let key = key_data.as_slice().try_into().unwrap();
            Box::new(Speck128_192::new_slice(key).unwrap())
        }
        "SPECK-128/256" => {
            let key_data = hex::decode(&vector.key).unwrap();
            let key = key_data.as_slice().try_into().unwrap();
            Box::new(Speck128_256::new_slice(key).unwrap())
        }
        _ => panic!("unknown type {}", vector.name),
    }
}

fn run_test_vector(vector: &Vector) {
    let cipher = create_cipher(vector);
    let mut plaintext = hex::decode(&vector.plaintext).unwrap();
    let ciphertext = hex::decode(&vector.ciphertext).unwrap();
    cipher.seal_in_place(&mut plaintext).unwrap();
    assert_eq!(plaintext, ciphertext);
}

#[test]
fn test_vectors() {
    let data: Data = toml::from_str(VECTORS).unwrap();
    for vector in data.vectors {
        run_test_vector(&vector);
    }
}

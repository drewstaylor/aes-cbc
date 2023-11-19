use std::cmp::Ordering;
use libaes::Cipher;
use hex::{encode as hex_encode};

#[derive(Debug)]
pub struct AesResult {
    encrypted: String,
    decrypted: String,
}

pub fn string_to_16_bytes(raw_target: String) -> Vec<u8> {
    let mut target = raw_target;
    let req_size: u8 = 16;
    let raw_len: u8 = target.clone().len() as u8;

    let ret: &[u8] = match raw_len.cmp(&req_size) {
        Ordering::Equal => {
            target.as_bytes()
        },
        Ordering::Less => {
            let pad_size: u8 = req_size - raw_len;
            for _ in 0..pad_size {
                target.push('0');
            }
            target.as_bytes()
        },
        Ordering::Greater => {
            let local_bytes = target.as_bytes();
            &local_bytes[0..16]
        },
    };

    ret.to_vec()
}

fn main() {
    let raw_key = "password".to_string();
    let raw_iv = "IV".to_string();
    let key: [u8; 16] = string_to_16_bytes(raw_key).try_into().expect("16 bytes");
    let iv: [u8; 16] = string_to_16_bytes(raw_iv).try_into().expect("16 bytes");
    let payload: String = "Some plaintext payload".to_string();
    let pt = payload.as_bytes();

    // Create 128-bit cipher stream
    let cipher = Cipher::new_128(&key);

    // Encrypt
    let encrypted = cipher.cbc_encrypt(&iv, pt);
    // Decrypt
    let decrypted = cipher.cbc_decrypt(&iv, &encrypted[..]);

    // Results
    let res = AesResult {
        encrypted: hex_encode(&encrypted),
        decrypted: String::from_utf8(decrypted).expect("Bytes should be valid utf8"),
    };
    println!("Encrypted {}", res.encrypted);
    println!("Decrypted {}", res.decrypted);
}
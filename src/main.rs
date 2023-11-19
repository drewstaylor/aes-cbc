use libaes::Cipher;
use hex::{encode as hex_encode};

#[derive(Debug)]
pub struct AesResult {
    encrypted: String,
    decrypted: String,
}

fn main() {
    let key = b"password00000000";  // 16 bytes, i.e. 128-bit compliant
    let iv = b"plain text000000";   // 16 bytes, i.e. 128-bit compliant
    let pt = b"Some plaintext payload";

    // Create 128-bit cipher stream
    let cipher = Cipher::new_128(key);

    // Encrypt
    let encrypted = cipher.cbc_encrypt(iv, pt);
    // Decrypt
    let decrypted = cipher.cbc_decrypt(iv, &encrypted[..]);

    // Results
    let res = AesResult {
        encrypted: hex_encode(&encrypted),
        decrypted: String::from_utf8(decrypted).expect("Bytes should be valid utf8"),
    };
    println!("Encrypted {}", res.encrypted);
    println!("Decrypted {}", res.decrypted);
}
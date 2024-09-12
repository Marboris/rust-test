use chacha20poly1305::aead::generic_array::typenum::Unsigned;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::ChaCha20Poly1305;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::prelude::*;
use std::io::Cursor;
use clap::Parser;
use hex;

/// ساختار برای پارامترهای ورودی خط فرمان
#[derive(Parser)]
struct Cli {
    /// داده برای رمزگذاری یا رمزگشایی
    #[arg(long)]
    data: String,

    /// نوع عملیات: encrypt یا decrypt
    #[arg(long)]
    operation_type: String,

    /// کلید برای رمزگشایی
    #[arg(long, default_value = "")]
    key: String,
}

pub fn generate_key() -> Vec<u8> {
    ChaCha20Poly1305::generate_key(&mut OsRng).to_vec()
}

pub fn compress_data(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

pub fn decompress_data(data: &[u8]) -> Vec<u8> {
    let mut decoder = GzDecoder::new(Cursor::new(data));
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data).unwrap();
    decompressed_data
}

pub fn encrypt(cleartext: &str, key: &[u8]) -> Vec<u8> {
    let compressed_data = compress_data(cleartext.as_bytes());
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut encrypted_data = cipher.encrypt(&nonce, &*compressed_data).unwrap();
    encrypted_data.splice(..0, nonce.iter().copied());
    encrypted_data
}

pub fn decrypt(encrypted_data: &[u8], key: &[u8]) -> String {
    type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let (nonce, ciphertext) = encrypted_data.split_at(NonceSize::to_usize());
    let nonce = GenericArray::from_slice(nonce);
    let compressed_data = cipher.decrypt(nonce, ciphertext).unwrap();
    let decompressed_data = decompress_data(&compressed_data);
    String::from_utf8(decompressed_data).unwrap()
}

fn main() {
    // دریافت ورودی از خط فرمان
    let args = Cli::parse();

    match args.operation_type.as_str() {
        "encrypt" => {
            let key = generate_key();
            let ciphertext = encrypt(&args.data, &key);
            println!("Encrypted Data: {}", hex::encode(&ciphertext));
            println!("Encryption Key: {}", hex::encode(&key));
        }
        "decrypt" => {
            // دریافت کلید از کاربر
            if args.key.is_empty() {
                println!("Error: No key provided for decryption.");
                return;
            }

            // تبدیل کلید از رشته به وکتور
            match hex::decode(&args.key) {
                Ok(key) => {
                    // تبدیل داده از رشته به بایت‌ها
                    match hex::decode(&args.data) {
                        Ok(encrypted_data) => {
                            let decrypted_text = decrypt(&encrypted_data, &key);
                            println!("Decrypted Data: {:?}", decrypted_text);
                        }
                        Err(e) => {
                            println!("Error: Invalid data format. Use hexadecimal. {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("Error: Invalid key format. Use hexadecimal. {:?}", e);
                }
            }
        }
        _ => {
            println!("Invalid operation type. Please use 'encrypt' or 'decrypt'.");
        }
    }
}

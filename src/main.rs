extern crate rand;

mod aes;

use std::vec::Vec;
use std::time::Instant;
use rand::Rng;


fn main() {
    let cipherkey: Vec<[u8; 4]> = vec![
        [0x00, 0x01, 0x02, 0x03],        
        [0x04, 0x05, 0x06, 0x07],
        [0x08, 0x09, 0x0a, 0x0b],
        [0x0c, 0x0d, 0x0e, 0x0f]
    ];
    let plaintext: Vec<u8> = (0..10_000_000)
        .map(|_| rand::thread_rng().gen())
        .collect();
    
    let now = Instant::now();
    let ciphertext = aes::cipher(&plaintext, &cipherkey);
    let elapsed = now.elapsed();
    
    println!("{}", elapsed.as_millis());
}

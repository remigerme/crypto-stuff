// Implemented according to FISP 198-1 https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.198-1.pdf

use super::{IO, SHAMode, hash, extract_digest};

fn hmac(k: &IO, text: &IO, mode: SHAMode) -> IO {
    let b = 128; // block size for all sha512 modes
    let ipad = vec![0x36u8; b];
    let opad = vec![0x5cu8; b];
    let mut text_ = text.clone();
    // Step 1-3 : determine k0
    let k0 = if k.len() == b { k.clone() } else {
        if k.len() > b {
            let mut k_ = extract_digest(hash(k, mode));
            k_.append(&mut vec![0u8; b - k_.len()]);
            k_
        } else { // k.len() < b
            let mut k_ = k.clone();
            k_.append(&mut vec![0u8; b - k.len()]);
            k_
        }
    };
    // Step 4 : xoring k0 and ipad
    let mut res: Vec<u8> = k0.iter().enumerate().map(|(i, x)| x ^ ipad[i]).collect();
    res.append(&mut text_); // step 5
    let mut res = extract_digest(hash(&res, mode)); // step 6
    // Step 7 : xoring k0 and opad
    let mut res_: Vec<u8> = k0.iter().enumerate().map(|(i, x)| x ^ opad[i]).collect();
    res_.append(&mut res); // step 8
    extract_digest(hash(&res_, mode)) // step 9
}
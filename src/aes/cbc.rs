// CBC implementation according to https://doi.org/10.6028/NIST.SP.800-38A

use super::{
    State, IO, MasterKey, ExpandedKey,
    n_rounds, io_to_state, state_to_io,
    xor_state, key_expansion, 
    cipher_state, inv_cipher_state
};


// See section 6.2
pub fn encrypt_cbc(plain: &IO, k: &MasterKey, iv: &State) -> IO {
    // PKCS#7 padding
    let n_padding: u8 = (16 - plain.len() % 16).try_into().unwrap();
    let mut plain: IO = plain.clone();
    plain.extend(vec![n_padding; n_padding as usize]);

    let nk = k.len(); 
    let nr = n_rounds(nk);
    let w: ExpandedKey = key_expansion(nk, &k);

    let mut states: Vec<State> = (0..(plain.len() / 16))
        .map(|i| io_to_state(&plain[16 * i .. 16 * (i + 1)].to_vec()))
        .collect();
    
    states[0] = xor_state(&states[0], &iv);
    cipher_state(&mut states[0], &w, nr);
    for i in 1..states.len() {
        states[i] = xor_state(&states[i], &states[i - 1]);
        cipher_state(&mut states[i], &w, nr);
    }

    states.iter()
    .flat_map(
        |s| state_to_io(s)
            .iter()
            .map(|&b| b)
            .collect::<Vec<u8>>())
    .collect()
}


pub fn decrypt_cbc(ciphertext: &IO, k: &MasterKey, iv: &State) -> IO {
    assert_eq!(0, ciphertext.len() % 16);

    let nk = k.len(); 
    let nr = n_rounds(nk);
    let w = key_expansion(nk, k);

    let mut states: Vec<State> = (0..(ciphertext.len() / 16))
        .map(|i| io_to_state(&ciphertext[16 * i .. 16 * (i + 1)].to_vec()))
        .collect();
    
    let mut previous_cipher_block = *iv;
    for s in states.iter_mut() {
        let current_cipher_block = s.clone();
        inv_cipher_state(s, &w, nr);
        *s = xor_state(s, &previous_cipher_block);
        previous_cipher_block = current_cipher_block;
    }
    
    let plain: IO = {
        states.iter()
              .flat_map(
                |s| state_to_io(s)
                  .iter()
                  .map(|&b| b)
                  .collect::<Vec<u8>>())
              .collect()
    };
    // PKCS#7 unpadding
    let n = *plain.last().unwrap();
    plain[0..plain.len() - n as usize].to_vec()
}

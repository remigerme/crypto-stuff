use std::vec::Vec;

type IO = Vec<u8>;

// prf takes IO and not &IO
// Because there's a lifetime problem
// I don't understand if I try with &IO
pub fn pbkdf2(
    prf: Box<dyn Fn(IO, IO) -> IO>,
    password: &IO,
    salt: &IO,
    c: usize,
    dk_len_bytes: usize,
    h_len_bytes: usize
) -> IO {
    // Let's check if dk_len_bytes, h_len_bytes and the prf function are consistent
    let sample = prf(vec![0], vec![0]);
    assert!(dk_len_bytes % h_len_bytes == 0);
    assert!(h_len_bytes % sample.len() == 0);

    let f = |i| {
        let vec_i = u32::to_be_bytes(i).to_vec();
        // Instead of keeping U1, ..., UC in a vec
        // We compute the final xor result step by step
        // And we consume the previous U to compute the next one
        let mut u = salt.clone();
        u.extend(vec_i);
        let mut res = vec![0; h_len_bytes];
        for _ in 1..=c {
            u = prf(password.clone(), u);
            // Xoring vects
            for i in 0..h_len_bytes {
                res[i] ^= u[i];
            }
        }
        res
    };
    let mut res = vec![];
    for i in 1..=dk_len_bytes / h_len_bytes {
        res.extend(f(i as u32));
    }
    res
}
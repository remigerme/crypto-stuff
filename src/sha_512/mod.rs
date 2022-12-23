// Implemented according to FIPS 180-4 : https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
// I implemented only SHA-512 and truncated versions (SHA-384, SHA-512/224, SHA-512/256).

use std::vec::Vec;

type Word = u64;
type Block = [Word; 16];
type Blocks = Vec<Block>;
type IO = Vec<u8>;


// See section 4.2.3
const K: [Word; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];


// Functions : see section 4.1.3
fn rotr(x: Word, n: u32) -> Word {
    x.rotate_right(n)
}

fn ch(x: Word, y: Word, z: Word) -> Word {
    (x & y) ^ (!x & z)
}

fn maj(x: Word, y: Word, z: Word) -> Word {
    (x & y) ^ (x & z) ^ (y & z)
}

fn sigma_cap_0(x: Word) -> Word {
    rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)
}

fn sigma_cap_1(x: Word) -> Word {
    rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)
}

fn sigma_0(x: Word) -> Word {
    rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)
}

fn sigma_1(x: Word) -> Word {
    rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6)
}


// See section 5.1.2
fn pad(m: &IO) -> IO {
    // m: l bits vec (ie l / 8 u8 vec)
    // by doing arithmetic we can easily prove
    // k % 8 = 7 (so k >= 1)
    let mut m = m.clone();
    let l = 8 * m.len();
    let l_ = l % 1024;
    let k = if l_ <= 895 {
        896 - 1 - l_
    } else {
        1024 - l_ - 1 + 896
    };
    m.push(0b10000000);
    m.extend(vec![0; k / 8]);
    m.extend(u128::to_be_bytes(l as u128));
    m
}


// See section 5.2.2
fn io_to_blocks(m: &IO) -> Blocks {
    assert!(m.len() % 128 == 0);
    let mut b = Vec::new();
    for i in (0..m.len()).step_by(128) {
        let mut block = Vec::new();
        for j in (0..128).step_by(8) {
            block.push(u64::from_be_bytes([
                m[i + j],
                m[i + j + 1],
                m[i + j + 2],
                m[i + j + 3],
                m[i + j + 4],
                m[i + j + 5],
                m[i + j + 6],
                m[i + j + 7]
            ]));
        }
        b.push(block.try_into().unwrap());
    }
    b
}


// See section 6.4.2
fn hash_blocks(b: &Blocks, hash: [Word; 8]) -> [Word; 8] {
    let mut hash = hash.clone();
    let n = b.len();
    for i in 1..=n {
        // 1 - Prepare the message schedule
        let mut w: Vec<Word> = b[i - 1].clone().to_vec();
        for t in 16..80 {
            w.push(sigma_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(sigma_0(w[t - 15]))
                .wrapping_add(w[t - 16])
            );
        }

        // 2 - Initialization of working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h]: [u64; 8] = hash;

        // 3
        for t in 0..80 {
            let t1 = h.wrapping_add(sigma_cap_1(e))
                  .wrapping_add(ch(e, f, g))
                  .wrapping_add(K[t])
                  .wrapping_add(w[t]);
            let t2 = sigma_cap_0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);

        }

        // 4 - Compute hash values
        hash[0] = a.wrapping_add(hash[0]);
        hash[1] = b.wrapping_add(hash[1]);
        hash[2] = c.wrapping_add(hash[2]);
        hash[3] = d.wrapping_add(hash[3]);
        hash[4] = e.wrapping_add(hash[4]);
        hash[5] = f.wrapping_add(hash[5]);
        hash[6] = g.wrapping_add(hash[6]);
        hash[7] = h.wrapping_add(hash[7]);
    }
    hash
}


// Useful function to truncate hash
fn hash_to_u8(h: [Word; 8]) -> Vec<u8> {
    h.iter()
     .flat_map(|&i| i.to_be_bytes())
     .collect()
}


// See section 5.3.5 and 6.4
fn hash_blocks_512(b: &Blocks) -> [u8; 64] {
    let hash = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    let h = hash_blocks(b, hash);
    let t = hash_to_u8(h);
    t[0..64].try_into().unwrap()
}

pub fn hash_512(m: &IO) -> [u8; 64] {
    let m = pad(m);
    let b = io_to_blocks(&m);
    hash_blocks_512(&b)
}


// See section 5.3.4 and 6.5
fn hash_blocks_384(b: &Blocks) -> [u8; 48] {
    let hash = [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    ];
    let h = hash_blocks(b, hash);
    let t = hash_to_u8(h);
    t[0..48].try_into().unwrap()
}

pub fn hash_384(m: &IO) -> [u8; 48] {
    let m = pad(m);
    let b = io_to_blocks(&m);
    hash_blocks_384(&b)
}


// See section 5.3.6.1 and 6.6
fn hash_blocks_512_224(b: &Blocks) -> [u8; 28] {
    let hash = [
        0x8C3D37C819544DA2,
        0x73E1996689DCD4D6,
        0x1DFAB7AE32FF9C82,
        0x679DD514582F9FCF,
        0x0F6D2B697BD44DA8,
        0x77E36F7304C48942,
        0x3F9D85A86A1D36C8,
        0x1112E6AD91D692A1,
    ];
    let h = hash_blocks(b, hash);
    let t = hash_to_u8(h);
    t[0..28].try_into().unwrap()
}

pub fn hash_512_224(m: &IO) -> [u8; 28] {
    let m = pad(m);
    let b = io_to_blocks(&m);
    hash_blocks_512_224(&b)
}


// See section 5.3.6.2 and 6.7
fn hash_blocks_512_256(b: &Blocks) -> [u8; 32] {
    let hash = [
        0x22312194FC2BF72C,
        0x9F555FA3C84C64C2,
        0x2393B86B6F53B151,
        0x963877195940EABD,
        0x96283EE2A88EFFE3,
        0xBE5E1E2553863992,
        0x2B0199FC2C85B8AA,
        0x0EB72DDC81C52CA2,
    ];
    let h = hash_blocks(b, hash);
    let t = hash_to_u8(h);
    t[0..32].try_into().unwrap()
}

pub fn hash_512_256(m: &IO) -> [u8; 32] {
    let m = pad(m);
    let b = io_to_blocks(&m);
    hash_blocks_512_256(&b)
}

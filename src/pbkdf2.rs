use std::vec::Vec;

type IO = Vec<u8>;


// Maybe a bit overkill for the situation
// But it was a nice exercise
// Concat 2 iterators
fn concat_2<T, A>(mut a: T, b: T) -> T
where
    T: IntoIterator<Item = A> + Extend<A>
{
    a.extend(b);
    a
}

// Concat together an iterator of iterators
fn concat<'a, S, T, A>(l: S) -> T
where
    T: IntoIterator<Item = A> + Extend<A> + Default,
    S: IntoIterator<Item = T>
{
    l.into_iter()
     .fold(T::default(), |x, y| concat_2(x, y))
}


pub fn pbkdf2(
    prf: Box<dyn Fn(&IO) -> IO>,
    password: &IO,
    salt: &IO,
    c: usize,
    dk_len_bytes: usize,
    h_len_bytes: usize
) -> IO {
    // Let's check if dk_len_bytes, h_len_bytes and the prf function are consistent
    let sample = prf(&vec![0]);
    assert!(dk_len_bytes % h_len_bytes == 0);
    assert!(h_len_bytes % sample.len() == 0);
    // Bad way to concat
    // For each call to f there is 2 * c clone of password and u elts
    // And there is dk_len_bytes / h_len_bytes calls to f
    // For now let's say it is intentional to make PBKD2
    // deliberately slower to compute...
    let f = |i| {
        let vec_i = u32::to_be_bytes(i).to_vec();
        let mut u = vec![
            prf(&concat([password.clone(), salt.clone(), vec_i]))
        ];
        for k in 1..c {
            u.push(prf(&concat([password.clone(), u[k - 1].clone()])));
        }
        // Xoring all vects together
        u.iter()
         .fold(vec![], |s: Vec<u8>, x|
             x.iter()
              .enumerate()
              .map(|(i, &e)| 
                  if i < s.len() {
                    e ^ s[i]
                  } else {
                    e
                  }).collect()
         )
    };
    // THIS DOESN'T COMPILE
    // Because concat expects an iterator containing
    // &Vec<u8> rather than Vec<u8>
    // Yet f(i as u32) yields a Vec<u8>
    concat(
        (1..=dk_len_bytes / h_len_bytes).map(|i| f(i as u32))
    )
}

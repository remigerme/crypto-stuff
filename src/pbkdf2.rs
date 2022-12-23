use std::vec::Vec;

type IO = Vec<u8>;


// Maybe a bit overkill for the situation
// But it was a nice exercise
// Concat 2 iterators
fn concat_2<T, A>(a: &T, b: &T) -> T
where
    A: Clone,
    T: IntoIterator<Item = A> + Extend<A>
{
    let mut c = *a.clone();
    c.extend(*b);
    c
}

// Concat together an iterator of iterators
fn concat<'a, S, T, A>(l: &S) -> T
where
    A: Clone,
    T: IntoIterator<Item = A> + Extend<A> + Default + 'a,
    S: IntoIterator<Item = &'a T>
{
    l.into_iter()
     .fold(T::default(), |x, y| concat_2(&x, &y))
}


pub fn pbkdf2(
    prf: Box<dyn Fn(&IO) -> IO>,
    password: &IO,
    salt: &IO,
    c: usize,
    dk_len: usize,
    h_len: usize
) -> IO { 
    let f = |i| {
        let vec_i = u32::to_be_bytes(i).to_vec();
        let mut u = vec![
            prf(&concat(&[password, salt, &vec_i]))
        ];
        for k in 1..c {
            u.push(prf(&concat(&[password, &u[k - 1]])));
            println!("{:?}", u[k - 1]);
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
        &(0..=dk_len / h_len).map(|i| f(i as u32))
    )
}

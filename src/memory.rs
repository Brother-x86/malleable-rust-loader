use log::debug;
use cryptify::encrypt_string;

// ----------- COMPILE TIME mEMORy
// MEMORY_1
#[rustfmt::skip]
#[cfg(not(feature="mem1"))]
static MEMORY_1 : &[u8] = &[];

#[rustfmt::skip]
#[cfg(all(feature="mem1",feature="ollvm"))]
static MEMORY_1 : &[u8] = include_bytes!("/projects/config/mem1");

#[rustfmt::skip]
#[cfg(all(feature="mem1",not(feature="ollvm")))]
static MEMORY_1 : &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/mem1"));

// MEMORY_2
#[rustfmt::skip]
#[cfg(not(feature="mem2"))]
static MEMORY_2 : &[u8] = &[];

#[rustfmt::skip]
#[cfg(all(feature="mem2",feature="ollvm"))]
static MEMORY_2 : &[u8] = include_bytes!("/projects/config/mem2");

#[rustfmt::skip]
#[cfg(all(feature="mem2",not(feature="ollvm")))]
static MEMORY_2 : &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/mem2"));

// MEMORY_3
#[rustfmt::skip]
#[cfg(not(feature="mem3"))]
static MEMORY_3 : &[u8] = &[];

#[rustfmt::skip]
#[cfg(all(feature="mem3",feature="ollvm"))]
static MEMORY_3 : &[u8] = include_bytes!("/projects/config/mem3");

#[rustfmt::skip]
#[cfg(all(feature="mem3",not(feature="ollvm")))]
static MEMORY_3 : &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/mem3"));

// MEMORY_4
#[rustfmt::skip]
#[cfg(not(feature="mem4"))]
static MEMORY_4 : &[u8] = &[];

#[rustfmt::skip]
#[cfg(all(feature="mem4",feature="ollvm"))]
static MEMORY_4 : &[u8] = include_bytes!("/projects/config/mem4");

#[rustfmt::skip]
#[cfg(all(feature="mem4",not(feature="ollvm")))]
static MEMORY_4 : &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/mem4"));

// ----------- COMPILE TIME mEMORy - end

pub fn access_memory(target:i32)-> Result<Vec<u8>, anyhow::Error>{
    debug!("{}{}", encrypt_string!("Access Memory: "), target);
    match target {
        1 => Ok(MEMORY_1.to_vec()),
        2 => Ok(MEMORY_2.to_vec()),
        3 => Ok(MEMORY_3.to_vec()),
        4 => Ok(MEMORY_4.to_vec()),
        //TODO raise Error here
        _ => Ok(vec![]),
    }

}
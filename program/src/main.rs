#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;
use alloc::vec::Vec;
use fibonacci_lib::{Fp, Sponge};

pub fn main() {
    let a: u64 = sp1_zkvm::io::read::<u64>();
    let b: u64 = sp1_zkvm::io::read::<u64>();

    let inputs: Vec<Fp> = [a, b].iter().map(|&v| Fp::from(v)).collect();
    let result = Sponge::hash(&inputs);

    sp1_zkvm::io::commit_slice(&result.to_be_bytes());
}

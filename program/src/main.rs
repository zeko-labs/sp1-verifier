#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;
use alloc::vec::Vec;
use fibonacci_lib::{Fp, Sponge};

pub fn main() {
    let a: u64 = sp1_zkvm::io::read::<u64>();
    let b: u64 = sp1_zkvm::io::read::<u64>();

    println!("cycle-tracker-start: poseidon");
    let inputs = [Fp::from(a), Fp::from(b)];
    let result = Sponge::hash(&inputs);
    println!("cycle-tracker-end: poseidon");

    sp1_zkvm::io::commit_slice(&result.to_be_bytes());
}

//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;
use alloc::{vec, vec::Vec};
use alloy_primitives::U256;

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let a: u64 = sp1_zkvm::io::read::<u64>();
    let b: u64 = sp1_zkvm::io::read::<u64>();

    let vec: Vec<U256> = vec![U256::from(a), U256::from(b)];
    let result = fibonacci_lib::hash(vec);

    let out: [u8; 32] = result.to_be_bytes();
    sp1_zkvm::io::commit_slice(&out);
}

#![no_main]
sp1_zkvm::entrypoint!(main);

use fibonacci_lib::{Fp, Sponge};

pub fn main() {
    let a: u64 = sp1_zkvm::io::read::<u64>();
    let b: u64 = sp1_zkvm::io::read::<u64>();

    println!("cycle-tracker-start: poseidon");
    let inputs = [Fp::from(a), Fp::from(b)];
    let result = Sponge::hash(&inputs);
    println!("cycle-tracker-end: poseidon");

    let hash_input_32: [Fp; 32] = std::array::from_fn(|i| Fp::from((i as u64) + 1));
    println!("cycle-tracker-start: poseidon_32");
    let result_32 = Sponge::hash(&hash_input_32);
    println!("poseidon_32 output: {:?}", result_32.to_be_bytes());
    println!("cycle-tracker-end: poseidon_32");

    sp1_zkvm::io::commit_slice(&result.to_be_bytes());
}

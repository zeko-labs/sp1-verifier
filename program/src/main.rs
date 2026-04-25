#![no_main]
sp1_zkvm::entrypoint!(main);

use core::array::from_fn;
use fibonacci_lib::{poseidon::Sponge, poseidon_hash, Fp};
use mina_curves::pasta::Fp as FpMina;

pub fn main() {
    let a: u64 = sp1_zkvm::io::read::<u64>();
    let b: u64 = sp1_zkvm::io::read::<u64>();

    let hash_input_32: [Fp; 32] = std::array::from_fn(|i| Fp::from((i as u64) + 1));
    println!("cycle-tracker-start: poseidon custom sp1");
    let result_32 = Sponge::hash(&hash_input_32);
    println!("cycle-tracker-end: poseidon custom sp1");
    println!(
        "poseidon_32 custom sp1 output: {:?}",
        result_32.to_decimal_string()
    );

    let hash_input_32: [FpMina; 32] = from_fn(|i| FpMina::from((i as u64) + 1));
    println!("cycle-tracker-start: poseidon mina");
    let hash_out = poseidon_hash(&hash_input_32);
    println!("cycle-tracker-end: poseidon mina");
    println!("poseidon_32 mina output: {:?}", hash_out);

    println!("cycle-tracker-start: poseidon");
    let inputs = [Fp::from(a), Fp::from(b)];
    let result = Sponge::hash(&inputs);
    println!("cycle-tracker-end: poseidon");

    sp1_zkvm::io::commit_slice(&result.to_be_bytes());
}

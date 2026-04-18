//! Run once to generate the static SRS with lagrange bases:
//! cargo run --release -p generate-srs

use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ledger::proofs::BACKEND_TOCK_ROUNDS_N;
use mina_curves::pasta::Pallas;
use poly_commitment::{ipa::SRS, SRS as SRSTrait};

fn main() {
    println!("Generating SRS with lagrange bases...");

    let degree = 1 << BACKEND_TOCK_ROUNDS_N; // 32768
    let mut srs = SRS::<Pallas>::create_parallel(degree);

    // Precalculate lagrange bases for the zkapp domain (log2_size = 15)
    let domain = Radix2EvaluationDomain::new(1 << 15).unwrap();
    srs.get_lagrange_basis(domain);

    let bytes = bincode::serialize(&srs).expect("serialize srs");

    let out_path = "program/src/srs_pallas.bin";
    std::fs::write(out_path, &bytes).expect("write srs");

    println!("✓ SRS written to {out_path} ({} bytes)", bytes.len());
}

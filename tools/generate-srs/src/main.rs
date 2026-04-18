//! Run once to generate the static SRS with lagrange bases:
//! cargo run --release -p generate-srs

use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ledger::proofs::BACKEND_TOCK_ROUNDS_N;
use mina_curves::pasta::{Fp, Pallas};
use poly_commitment::{ipa::SRS, SRS as SRSTrait};

fn main() {
    println!("Generating SRS with lagrange bases...");

    let degree = 1 << BACKEND_TOCK_ROUNDS_N;
    println!("  degree: {}", degree);

    let mut srs = SRS::<Pallas>::create_parallel(degree);
    println!("  SRS created");

    // Precalculate lagrange bases for the zkapp domain (log2_size = 15)
    let domain = Radix2EvaluationDomain::new(1 << 15).unwrap();
    srs.get_lagrange_basis(domain);
    println!("  lagrange bases computed");

    // Serialize SRS (g + h only — lagrange_bases are #[serde(skip)])
    let srs_bytes = bincode::serialize(&srs).expect("serialize srs");

    // Serialize lagrange bases separately
    let bases = srs.get_lagrange_basis_from_domain_size(1 << 15);
    let bases_bytes = bincode::serialize(bases).expect("serialize bases");

    std::fs::create_dir_all("program/src").expect("create program/src");
    std::fs::write("program/src/srs_pallas.bin", &srs_bytes).expect("write srs_pallas.bin");
    std::fs::write("program/src/lagrange_bases.bin", &bases_bytes)
        .expect("write lagrange_bases.bin");

    println!("✓ srs_pallas.bin:     {} bytes", srs_bytes.len());
    println!("✓ lagrange_bases.bin: {} bytes", bases_bytes.len());
    println!("Done — commit both files to the repo.");
}

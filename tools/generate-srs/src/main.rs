//! Run once to generate the static SRS with lagrange bases:
//! cargo run --release -p generate-srs

use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ledger::{
    proofs::{verifiers::make_zkapp_verifier_index, BACKEND_TOCK_ROUNDS_N},
    VerificationKey,
};
use mina_curves::pasta::{Fp, Pallas};
use mina_p2p_messages::v2::MinaBaseVerificationKeyWireStableV1;
use poly_commitment::{ipa::SRS, SRS as SRSTrait};

fn main() {
    println!("Generating SRS with lagrange bases...");

    // ------------------------------------------------------------------
    // 1. Load VK to get the real domain size
    // ------------------------------------------------------------------
    let vk_b64 = std::fs::read_to_string("proofs/vk.txt").expect("read proofs/vk.txt");
    let vk_wire =
        MinaBaseVerificationKeyWireStableV1::from_base64(vk_b64.trim()).expect("decode vk base64");
    let vk: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime");

    let verifier_index = make_zkapp_verifier_index(&vk);
    let domain_size = verifier_index.domain.size();
    println!(
        "  domain_size: {} (1 << {})",
        domain_size,
        domain_size.trailing_zeros()
    );

    // ------------------------------------------------------------------
    // 2. Create SRS and compute lagrange bases for the real domain
    // ------------------------------------------------------------------
    let degree = 1 << BACKEND_TOCK_ROUNDS_N;
    println!("  srs degree:  {}", degree);

    let mut srs = SRS::<Pallas>::create_parallel(degree);
    println!("  SRS created");

    let domain = Radix2EvaluationDomain::new(domain_size).unwrap();
    srs.get_lagrange_basis(domain);
    println!("  lagrange bases computed for domain_size={}", domain_size);

    // ------------------------------------------------------------------
    // 3. Serialize SRS (g + h only — lagrange_bases are #[serde(skip)])
    // ------------------------------------------------------------------
    let srs_bytes = bincode::serialize(&srs).expect("serialize srs");

    // ------------------------------------------------------------------
    // 4. Serialize lagrange bases separately with their domain_size key
    // ------------------------------------------------------------------
    let bases = srs.get_lagrange_basis_from_domain_size(domain_size);
    let bases_bytes = bincode::serialize(bases).expect("serialize bases");

    // Also serialize domain_size so the guest uses the exact same key
    let domain_size_bytes = bincode::serialize(&domain_size).expect("serialize domain_size");

    // ------------------------------------------------------------------
    // 5. Write files to program/src/ for include_bytes!
    // ------------------------------------------------------------------
    std::fs::create_dir_all("program/src").expect("create program/src");

    std::fs::write("program/src/srs_pallas.bin", &srs_bytes).expect("write srs_pallas.bin");
    std::fs::write("program/src/lagrange_bases.bin", &bases_bytes)
        .expect("write lagrange_bases.bin");
    std::fs::write("program/src/domain_size.bin", &domain_size_bytes)
        .expect("write domain_size.bin");

    println!("✓ srs_pallas.bin:     {} bytes", srs_bytes.len());
    println!("✓ lagrange_bases.bin: {} bytes", bases_bytes.len());
    println!("✓ domain_size.bin:    {} bytes", domain_size_bytes.len());
    println!("Done — commit all three files to the repo.");
}

//! Run once to generate the static SRS with lagrange bases (rkyv format):
//! cargo run --release -p generate-srs

use ark_poly::Radix2EvaluationDomain;
use ledger::{
    proofs::{verifiers::make_zkapp_verifier_index, BACKEND_TOCK_ROUNDS_N},
    VerificationKey,
};
use mina_curves::pasta::{Fp, Pallas};
use mina_p2p_messages::v2::MinaBaseVerificationKeyWireStableV1;
use poly_commitment::{ipa::SRS, SRS as SRSTrait};
use zeko_sp1_lib::{RkyvPoint, RkyvPolyComm, RkyvSRS};

fn point_to_flat(p: &Pallas) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[..32].copy_from_slice(&bytemuck::bytes_of(&p.x.0 .0));
    out[32..64].copy_from_slice(&bytemuck::bytes_of(&p.y.0 .0));
    out[64] = p.infinity as u8;
    out
}

fn main() {
    println!("Generating rkyv SRS with lagrange bases...");

    // ------------------------------------------------------------------
    // 1. Load VK to get the real domain size
    // ------------------------------------------------------------------
    let vk_b64 = std::fs::read_to_string("proofs/vk.txt").expect("read proofs/vk.txt");
    let vk_wire =
        MinaBaseVerificationKeyWireStableV1::from_base64(vk_b64.trim()).expect("decode vk base64");
    let vk: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime");

    let verifier_index = make_zkapp_verifier_index(&vk);

    use ark_poly::EvaluationDomain;
    let domain_size = verifier_index.domain.size();
    println!(
        "  domain_size: {} (1 << {})",
        domain_size,
        domain_size.trailing_zeros()
    );

    // ------------------------------------------------------------------
    // 2. Create SRS and compute lagrange bases
    // ------------------------------------------------------------------
    let degree = 1 << BACKEND_TOCK_ROUNDS_N;
    println!("  srs degree:  {}", degree);

    let mut srs = SRS::<Pallas>::create_parallel(degree);
    println!("  SRS created ({} points)", srs.g.len());

    let domain = Radix2EvaluationDomain::new(domain_size).unwrap();
    srs.get_lagrange_basis(domain);
    println!("  lagrange bases computed");

    // ------------------------------------------------------------------
    // 3. Convert to rkyv-serializable structs
    // ------------------------------------------------------------------
    println!("  converting to rkyv format...");

    let bases = srs.get_lagrange_basis_from_domain_size(domain_size);

    let rkyv_srs = RkyvSRS {
        g_flat: srs.g.iter().map(point_to_flat).collect(),
        h_flat: point_to_flat(&srs.h),
        domain_size,
        lagrange_flat: bases.iter().map(|c| point_to_flat(&c.chunks[0])).collect(),
    };

    println!("  g points:        {}", rkyv_srs.g_flat.len());
    println!("  lagrange_bases:  {}", rkyv_srs.lagrange_flat.len());

    // ------------------------------------------------------------------
    // 4. Serialize with rkyv
    // ------------------------------------------------------------------
    let rkyv_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&rkyv_srs).expect("rkyv serialize srs");

    // ------------------------------------------------------------------
    // 5. Write single file to program/src/
    // ------------------------------------------------------------------
    std::fs::create_dir_all("program/src").expect("create program/src");
    std::fs::write("program/src/srs_rkyv.bin", &rkyv_bytes).expect("write srs_rkyv.bin");

    println!("✓ srs_rkyv.bin: {} bytes", rkyv_bytes.len());
    println!("Done — commit program/src/srs_rkyv.bin to the repo.");
    println!("You can now delete: srs_pallas.bin, lagrange_bases.bin, domain_size.bin");
}

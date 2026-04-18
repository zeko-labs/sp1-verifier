#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_serialize::CanonicalDeserialize;
use bincode;
use kimchi::{
    circuits::constraints::FeatureFlags, groupmap::GroupMap, linearization::expr_linearization,
    mina_curves::pasta::PallasParameters,
};
use ledger::{
    proofs::{
        prover::make_padded_proof_from_p2p,
        transaction::{endos, InnerCurve},
        VerifierIndex,
    },
    VerificationKey,
};
use mina_curves::pasta::{Fp, Fq, Pallas};
use mina_p2p_messages::v2::{
    MinaBaseVerificationKeyWireStableV1, PicklesProofProofsVerified2ReprStableV2,
};
use mina_poseidon::sponge::{DefaultFqSponge, DefaultFrSponge};
use poly_commitment::{
    hash_map_cache::HashMapCache,
    ipa::{OpeningProof, SRS},
};
use std::{collections::HashMap, sync::Arc};
use zeko_sp1_lib::ZkappPublicValues;

const FULL_ROUNDS: usize = 55;
type SpongeParams = mina_poseidon::constants::PlonkSpongeConstantsKimchi;
type EFqSponge = DefaultFqSponge<PallasParameters, SpongeParams, FULL_ROUNDS>;
type EFrSponge = DefaultFrSponge<Fq, SpongeParams, FULL_ROUNDS>;

// SRS with lagrange bases — precomputed once, embedded in ELF
// Zero cost at runtime, no recalculation needed
static SRS_BYTES: &[u8] = include_bytes!("srs_pallas.bin");
static BASES_BYTES: &[u8] = include_bytes!("lagrange_bases.bin");
static DOMAIN_BYTES: &[u8] = include_bytes!("domain_size.bin");

pub fn main() {
    // ------------------------------------------------------------------
    // 1. Read inputs using read_vec for large buffers (zero-copy path)
    // ------------------------------------------------------------------
    let vk_wire: MinaBaseVerificationKeyWireStableV1 = sp1_zkvm::io::read();
    let proof: PicklesProofProofsVerified2ReprStableV2 = sp1_zkvm::io::read();
    let public_inputs_raw = sp1_zkvm::io::read_vec();
    let verifier_index_raw = sp1_zkvm::io::read_vec();

    // ------------------------------------------------------------------
    // 2. Deserialize public inputs — 40 x 32 bytes
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: deserialize_inputs");
    let public_inputs_bytes: Vec<[u8; 32]> =
        bincode::deserialize(&public_inputs_raw).expect("deserialize public_inputs");

    let public_inputs: Vec<Fq> = public_inputs_bytes
        .iter()
        .map(|b| Fq::deserialize_uncompressed(&b[..]).expect("deserialize Fq"))
        .collect();
    println!("cycle-tracker-end: deserialize_inputs");

    // ------------------------------------------------------------------
    // 3. Deserialize VerifierIndex (no SRS — we use the static one)
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: deserialize_verifier_index");
    let mut verifier_index: VerifierIndex<Fq> =
        bincode::deserialize(&verifier_index_raw).expect("deserialize verifier_index");
    println!("cycle-tracker-end: deserialize_verifier_index");

    // ------------------------------------------------------------------
    // 4. Attach static SRS (lagrange bases already included)
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: load_static_srs");
    let domain_size: usize = bincode::deserialize(DOMAIN_BYTES).expect("domain_size");
    let bases: Vec<poly_commitment::PolyComm<Pallas>> =
        bincode::deserialize(BASES_BYTES).expect("bases");

    let mut map = std::collections::HashMap::new();
    map.insert(domain_size, bases);

    let mut srs: SRS<Pallas> = bincode::deserialize(SRS_BYTES).expect("srs");
    srs.lagrange_bases = poly_commitment::hash_map_cache::HashMapCache::new_from_hashmap(map);

    verifier_index.srs = Arc::new(srs);
    println!("cycle-tracker-end: load_static_srs");

    // ------------------------------------------------------------------
    // 5. Reconstruct cheap skipped fields
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: reconstruct_skip_fields");
    let feature_flags = FeatureFlags::default();
    let (linearization, powers_of_alpha) = expr_linearization(Some(&feature_flags), true);
    let (endo_q, _) = endos::<Fq>();
    verifier_index.linearization = linearization;
    verifier_index.powers_of_alpha = powers_of_alpha;
    verifier_index.endo = endo_q;
    println!("cycle-tracker-end: reconstruct_skip_fields");

    // ------------------------------------------------------------------
    // 6. Verify integrity — check commitments match VK without full rebuild
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: verify_integrity");
    let vk: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime");
    let make_poly = |poly: &InnerCurve<Fp>| poly_commitment::PolyComm {
        chunks: vec![poly.to_affine()],
    };
    assert_eq!(
        verifier_index.generic_comm,
        make_poly(&vk.wrap_index.generic),
        "generic_comm mismatch"
    );
    assert_eq!(
        verifier_index.sigma_comm,
        vk.wrap_index.sigma.each_ref().map(make_poly),
        "sigma_comm mismatch"
    );
    println!("cycle-tracker-end: verify_integrity");

    // ------------------------------------------------------------------
    // 7. Pad proof + group map
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: make_padded_proof");
    let prover_proof = make_padded_proof_from_p2p(&proof).expect("padded proof");
    println!("cycle-tracker-end: make_padded_proof");

    println!("cycle-tracker-start: group_map_setup");
    let group_map = GroupMap::<Fp>::setup();
    println!("cycle-tracker-end: group_map_setup");

    // ------------------------------------------------------------------
    // 8. Kimchi verify
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: kimchi_verify");
    let result = kimchi::verifier::verify::<
        FULL_ROUNDS,
        Pallas,
        EFqSponge,
        EFrSponge,
        OpeningProof<Pallas, FULL_ROUNDS>,
    >(&group_map, &verifier_index, &prover_proof, &public_inputs);
    println!("cycle-tracker-end: kimchi_verify");

    let proof_valid = result.is_ok();
    assert!(proof_valid, "Kimchi verify failed: {:?}", result.err());

    sp1_zkvm::io::commit(&ZkappPublicValues { proof_valid });
}

#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_serialize::CanonicalDeserialize;
use core::array::from_fn;
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
use zeko_sp1_lib::{poseidon_hash, ArchivedRkyvSRS, ZkappPublicValues};

const FULL_ROUNDS: usize = 55;
type SpongeParams = mina_poseidon::constants::PlonkSpongeConstantsKimchi;
type EFqSponge = DefaultFqSponge<PallasParameters, SpongeParams, FULL_ROUNDS>;
type EFrSponge = DefaultFrSponge<Fq, SpongeParams, FULL_ROUNDS>;

// SRS with lagrange bases — precomputed once, embedded in ELF
static SRS_RKYV: &[u8] = include_bytes!("srs_rkyv.bin");

pub fn main() {
    // ------------------------------------------------------------------
    // 1. Read inputs
    // ------------------------------------------------------------------
    let vk_wire: MinaBaseVerificationKeyWireStableV1 = sp1_zkvm::io::read();
    let proof: PicklesProofProofsVerified2ReprStableV2 = sp1_zkvm::io::read();
    let public_inputs_raw = sp1_zkvm::io::read_vec();
    let verifier_index_raw = sp1_zkvm::io::read_vec();

    // ------------------------------------------------------------------
    // 2. Deserialize public inputs from raw 32-byte chunks
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: deserialize_inputs");
    assert!(
        public_inputs_raw.len() % 32 == 0,
        "public_inputs_raw length must be a multiple of 32"
    );

    let public_inputs: Vec<Fq> = public_inputs_raw
        .chunks_exact(32)
        .map(|chunk| Fq::deserialize_uncompressed(chunk).expect("deserialize Fq"))
        .collect();
    println!("cycle-tracker-end: deserialize_inputs");

    // ------------------------------------------------------------------
    // 3. Deserialize VerifierIndex (still bincode)
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: deserialize_verifier_index");
    let mut verifier_index: VerifierIndex<Fq> =
        bincode::deserialize(&verifier_index_raw).expect("deserialize verifier_index");
    println!("cycle-tracker-end: deserialize_verifier_index");

    // ------------------------------------------------------------------
    // 4. Attach static SRS (lagrange bases already included)
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: load_static_srs");
    let archived = unsafe { rkyv::access_unchecked::<ArchivedRkyvSRS>(SRS_RKYV) };

    let g: Vec<Pallas> = archived
        .g
        .iter()
        .map(|p| {
            let x = mina_curves::pasta::Fp::deserialize_uncompressed(&p.x[..]).unwrap();
            let y = mina_curves::pasta::Fp::deserialize_uncompressed(&p.y[..]).unwrap();
            Pallas::new(x, y)
        })
        .collect();

    let h: Pallas = {
        let p = &archived.h;
        let x = mina_curves::pasta::Fp::deserialize_uncompressed(&p.x[..]).unwrap();
        let y = mina_curves::pasta::Fp::deserialize_uncompressed(&p.y[..]).unwrap();
        Pallas::new(x, y)
    };

    let lagrange_bases: Vec<poly_commitment::PolyComm<Pallas>> = archived
        .lagrange_bases
        .iter()
        .map(|comm| poly_commitment::PolyComm {
            chunks: comm
                .chunks
                .iter()
                .map(|p| {
                    let x = mina_curves::pasta::Fp::deserialize_uncompressed(&p.x[..]).unwrap();
                    let y = mina_curves::pasta::Fp::deserialize_uncompressed(&p.y[..]).unwrap();
                    Pallas::new(x, y)
                })
                .collect(),
        })
        .collect();

    let domain_size = archived.domain_size.to_native();
    let mut map = HashMap::new();
    map.insert(domain_size.try_into().unwrap(), lagrange_bases);

    let srs = SRS::<Pallas> {
        g,
        h,
        lagrange_bases: HashMapCache::new_from_hashmap(map),
    };

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
    // 6. Verify integrity
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

    // ------------------------------------------------------------------
    // 9. Benchmark Poseidon hash on exactly 32 Fp elements
    // ------------------------------------------------------------------
    let hash_input_32: [Fp; 32] = from_fn(|i| Fp::from((i as u64) + 1));

    println!("cycle-tracker-start: poseidon_hash_32");
    let hash_out = poseidon_hash(&hash_input_32);
    println!("poseidon_32 output: {:?}", hash_out);
    println!("cycle-tracker-end: poseidon_hash_32");

    sp1_zkvm::io::commit(&ZkappPublicValues { proof_valid });
}

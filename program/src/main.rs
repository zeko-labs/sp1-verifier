#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kimchi::{
    circuits::constraints::FeatureFlags, groupmap::GroupMap, linearization::expr_linearization,
    mina_curves::pasta::PallasParameters,
};
use ledger::proofs::public_input::plonk_checks::ShiftedValue;
use ledger::proofs::public_input::prepared_statement::{DeferredValues, Plonk};
use ledger::proofs::step::FeatureFlags as LFF;
use ledger::scan_state::transaction_logic::zkapp_statement::ZkappStatement;
use ledger::{
    proofs::{
        prover::make_padded_proof_from_p2p,
        transaction::{endos, InnerCurve},
        verification::{
            get_message_for_next_step_proof, get_message_for_next_wrap_proof,
            get_prepared_statement, VK,
        },
        VerifierIndex,
    },
    VerificationKey,
};
use mina_curves::pasta::{Fp, Fq, Pallas};
use mina_p2p_messages::v2::{
    CompositionTypesBranchDataDomainLog2StableV1, CompositionTypesBranchDataStableV1,
    MinaBaseVerificationKeyWireStableV1, PicklesBaseProofsVerifiedStableV1,
    PicklesProofProofsVerified2ReprStableV2,
};
use mina_poseidon::sponge::{DefaultFqSponge, DefaultFrSponge};
use poly_commitment::{
    hash_map_cache::HashMapCache,
    ipa::{OpeningProof, SRS},
};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use zeko_sp1_lib::{ArchivedRkyvSRS, SerializableDeferredValues, ZkappPublicValues};

const FULL_ROUNDS: usize = 55;
type SpongeParams = mina_poseidon::constants::PlonkSpongeConstantsKimchi;
type EFqSponge = DefaultFqSponge<PallasParameters, SpongeParams, FULL_ROUNDS>;
type EFrSponge = DefaultFrSponge<Fq, SpongeParams, FULL_ROUNDS>;

static SRS_RKYV: &[u8] = include_bytes!("srs_rkyv.bin");

// Helpers définis au niveau module pour éviter les conflits
#[inline(always)]
fn deserialize_fp(b: [u8; 32]) -> Fp {
    Fp::deserialize_uncompressed(&b[..]).unwrap()
}

#[inline(always)]
fn to_shifting(b: [u8; 32]) -> ShiftedValue<Fp> {
    ShiftedValue {
        shifted: deserialize_fp(b),
    }
}

#[inline(always)]
fn montgomery_bytes_to_fp(bytes: &[u8; 32]) -> Fp {
    unsafe {
        let limbs: [u64; 4] = bytemuck::cast(*bytes);
        core::mem::transmute(limbs)
    }
}

#[inline(always)]
fn rkyv_to_pallas(p: &zeko_sp1_lib::ArchivedRkyvPoint) -> Pallas {
    if p.infinity {
        return Pallas::default();
    }
    Pallas::new_unchecked(montgomery_bytes_to_fp(&p.x), montgomery_bytes_to_fp(&p.y))
}

pub fn main() {
    // ------------------------------------------------------------------
    // 1. Read inputs
    // ------------------------------------------------------------------
    let vk_wire: MinaBaseVerificationKeyWireStableV1 = sp1_zkvm::io::read();
    let proof: PicklesProofProofsVerified2ReprStableV2 = sp1_zkvm::io::read();
    let zkapp_stmt_raw = sp1_zkvm::io::read_vec();
    let deferred_values_raw = sp1_zkvm::io::read_vec();
    let verifier_index_raw = sp1_zkvm::io::read_vec();

    // ------------------------------------------------------------------
    // 2. Deserialize inputs
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: deserialize_inputs");

    let zkapp_stmt: ZkappStatement =
        bincode::deserialize(&zkapp_stmt_raw).expect("deserialize zkapp_stmt");

    let sdv: SerializableDeferredValues =
        bincode::deserialize(&deferred_values_raw).expect("deserialize deferred_values");

    let deferred_values = DeferredValues {
        plonk: Plonk {
            alpha: sdv.plonk.alpha,
            beta: sdv.plonk.beta,
            gamma: sdv.plonk.gamma,
            zeta: sdv.plonk.zeta,
            zeta_to_srs_length: to_shifting(sdv.plonk.zeta_to_srs_length),
            zeta_to_domain_size: to_shifting(sdv.plonk.zeta_to_domain_size),
            perm: to_shifting(sdv.plonk.perm),
            lookup: sdv.plonk.lookup,
            feature_flags: LFF {
                range_check0: sdv.plonk.feature_flags_range_check0,
                range_check1: sdv.plonk.feature_flags_range_check1,
                foreign_field_add: sdv.plonk.feature_flags_foreign_field_add,
                foreign_field_mul: sdv.plonk.feature_flags_foreign_field_mul,
                xor: sdv.plonk.feature_flags_xor,
                rot: sdv.plonk.feature_flags_rot,
                lookup: sdv.plonk.feature_flags_lookup,
                runtime_tables: sdv.plonk.feature_flags_runtime_tables,
            },
        },
        combined_inner_product: to_shifting(sdv.combined_inner_product),
        b: to_shifting(sdv.b),
        xi: sdv.xi,
        bulletproof_challenges: sdv
            .bulletproof_challenges
            .iter()
            .map(|b| deserialize_fp(*b))
            .collect(),
        branch_data: CompositionTypesBranchDataStableV1 {
            proofs_verified: match sdv.branch_data_proofs_verified {
                0 => PicklesBaseProofsVerifiedStableV1::N0,
                1 => PicklesBaseProofsVerifiedStableV1::N1,
                _ => PicklesBaseProofsVerifiedStableV1::N2,
            },
            domain_log2: CompositionTypesBranchDataDomainLog2StableV1(
                sdv.branch_data_domain_log2.into(),
            ),
        },
    };

    println!("cycle-tracker-end: deserialize_inputs");

    // ------------------------------------------------------------------
    // 3. Deserialize VerifierIndex
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: deserialize_verifier_index");
    let mut verifier_index: VerifierIndex<Fq> =
        bincode::deserialize(&verifier_index_raw).expect("deserialize verifier_index");
    println!("cycle-tracker-end: deserialize_verifier_index");

    // ------------------------------------------------------------------
    // 4. Load static SRS
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: load_static_srs");
    let archived = unsafe { rkyv::access_unchecked::<ArchivedRkyvSRS>(SRS_RKYV) };

    let g: Vec<Pallas> = archived.g.iter().map(|p| rkyv_to_pallas(p)).collect();
    let h: Pallas = rkyv_to_pallas(&archived.h);
    let lagrange_bases: Vec<poly_commitment::PolyComm<Pallas>> = archived
        .lagrange_bases
        .iter()
        .map(|comm| poly_commitment::PolyComm {
            chunks: comm.chunks.iter().map(|p| rkyv_to_pallas(p)).collect(),
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
    // 5. Reconstruct skipped fields
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
        make_poly(&vk.wrap_index.generic)
    );
    assert_eq!(
        verifier_index.sigma_comm,
        vk.wrap_index.sigma.each_ref().map(make_poly)
    );
    println!("cycle-tracker-end: verify_integrity");

    // ------------------------------------------------------------------
    // 7. Compute public inputs from zkapp_stmt
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: compute_public_inputs");
    let vk_wrapper = VK {
        commitments: *vk.wrap_index.clone(),
        index: &verifier_index,
        data: (),
    };

    let msg_next_step = get_message_for_next_step_proof(
        &proof.statement.messages_for_next_step_proof,
        &vk_wrapper.commitments,
        &zkapp_stmt,
    )
    .expect("get_message_for_next_step_proof");

    let msg_next_wrap =
        get_message_for_next_wrap_proof(&proof.statement.proof_state.messages_for_next_wrap_proof)
            .expect("get_message_for_next_wrap_proof");

    let prepared = get_prepared_statement(
        &msg_next_step,
        &msg_next_wrap,
        deferred_values,
        &proof.statement.proof_state.sponge_digest_before_evaluations,
    );

    let public_inputs: Vec<Fq> = prepared
        .to_public_input(vk_wrapper.index.public)
        .expect("prepared -> public inputs");

    println!("cycle-tracker-end: compute_public_inputs");

    // ------------------------------------------------------------------
    // 8. Pad proof + group map
    // ------------------------------------------------------------------
    println!("cycle-tracker-start: make_padded_proof");
    let prover_proof = make_padded_proof_from_p2p(&proof).expect("padded proof");
    println!("cycle-tracker-end: make_padded_proof");

    println!("cycle-tracker-start: group_map_setup");
    let group_map = GroupMap::<Fp>::setup();
    println!("cycle-tracker-end: group_map_setup");

    // ------------------------------------------------------------------
    // 9. Kimchi verify
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
    // 10. Commit public values
    // ------------------------------------------------------------------
    let vk_hash: [u8; 32] = Sha256::digest(&verifier_index_raw).into();

    let app_state: Vec<[u8; 32]> = zkapp_stmt
        .to_field_elements()
        .iter()
        .map(|f: &Fp| {
            let mut buf = [0u8; 32];
            f.serialize_uncompressed(&mut buf[..]).unwrap();
            buf
        })
        .collect();

    sp1_zkvm::io::commit(&ZkappPublicValues {
        proof_valid,
        vk_hash,
        app_state,
    });
}

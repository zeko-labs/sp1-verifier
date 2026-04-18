#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_serialize::CanonicalDeserialize;
use kimchi::{groupmap::GroupMap, mina_curves::pasta::PallasParameters};
use ledger::{
    proofs::{prover::make_padded_proof_from_p2p, verifiers::make_zkapp_verifier_index},
    VerificationKey,
};
use mina_curves::pasta::{Fp, Fq, Pallas};
use mina_p2p_messages::v2::{
    MinaBaseVerificationKeyWireStableV1, PicklesProofProofsVerified2ReprStableV2,
};
use mina_poseidon::sponge::{DefaultFqSponge, DefaultFrSponge};
use poly_commitment::ipa::OpeningProof;
use zeko_sp1_lib::ZkappPublicValues;

const FULL_ROUNDS: usize = 55;
type SpongeParams = mina_poseidon::constants::PlonkSpongeConstantsKimchi;
type EFqSponge = DefaultFqSponge<PallasParameters, SpongeParams, FULL_ROUNDS>;
type EFrSponge = DefaultFrSponge<Fq, SpongeParams, FULL_ROUNDS>;

pub fn main() {
    // ------------------------------------------------------------------
    // 1. Read inputs — all precomputed on host except vk_wire + proof
    // ------------------------------------------------------------------
    let vk_wire: MinaBaseVerificationKeyWireStableV1 = sp1_zkvm::io::read();
    let proof: PicklesProofProofsVerified2ReprStableV2 = sp1_zkvm::io::read();
    let public_inputs_bytes: Vec<[u8; 32]> = sp1_zkvm::io::read();

    // ------------------------------------------------------------------
    // 2. Deserialize public inputs
    // ------------------------------------------------------------------
    let public_inputs: Vec<Fq> = public_inputs_bytes
        .iter()
        .map(|b| Fq::deserialize_uncompressed(&b[..]).expect("deserialize Fq"))
        .collect();

    // ------------------------------------------------------------------
    // 3. Reconstruct verifier index + prover proof in guest
    //    (these types don't implement CanonicalDeserialize)
    // ------------------------------------------------------------------
    let vk: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime");
    let verifier_index = make_zkapp_verifier_index(&vk);
    let prover_proof = make_padded_proof_from_p2p(&proof).expect("padded proof");

    // ------------------------------------------------------------------
    // 4. Kimchi verify ONLY — no run_checks, no Pickles
    // ------------------------------------------------------------------
    let group_map = GroupMap::<Fp>::setup();

    let result = kimchi::verifier::verify::<
        FULL_ROUNDS,
        Pallas,
        EFqSponge,
        EFrSponge,
        OpeningProof<Pallas, FULL_ROUNDS>,
    >(&group_map, &verifier_index, &prover_proof, &public_inputs);

    let proof_valid = result.is_ok();
    assert!(proof_valid, "Kimchi verify failed: {:?}", result.err());

    sp1_zkvm::io::commit(&ZkappPublicValues { proof_valid });
}

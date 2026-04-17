#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_serialize::CanonicalDeserialize;
use ledger::{
    proofs::{
        prover::make_padded_proof_from_p2p,
        verification::{run_checks, verify_with},
        verifiers::make_zkapp_verifier_index,
    },
    VerificationKey,
};
use mina_curves::pasta::Fq;
use mina_p2p_messages::v2::{
    MinaBaseVerificationKeyWireStableV1, PicklesProofProofsVerified2ReprStableV2,
};
use zeko_sp1_lib::ZkappPublicValues;

pub fn main() {
    // ------------------------------------------------------------------
    // 1. Read inputs
    //    1. vk_wire
    //    2. proof (raw, for run_checks)
    //    3. public_inputs as Vec<[u8; 32]> (precomputed on host)
    // ------------------------------------------------------------------
    let vk_wire: MinaBaseVerificationKeyWireStableV1 = sp1_zkvm::io::read();
    let proof: PicklesProofProofsVerified2ReprStableV2 = sp1_zkvm::io::read();
    let public_inputs_bytes: Vec<[u8; 32]> = sp1_zkvm::io::read();

    // ------------------------------------------------------------------
    // 2. Reconstruct Fq public inputs from bytes
    // ------------------------------------------------------------------
    let public_inputs: Vec<Fq> = public_inputs_bytes
        .iter()
        .map(|b| Fq::deserialize_uncompressed(&b[..]).expect("deserialize Fq"))
        .collect();

    // ------------------------------------------------------------------
    // 3. Reconstruct verifier index from VK
    // ------------------------------------------------------------------
    let vk: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime");
    let verifier_index = make_zkapp_verifier_index(&vk);

    // ------------------------------------------------------------------
    // 4. run_checks — verifies Pickles-level consistency
    // ------------------------------------------------------------------
    let checks_ok = run_checks(&proof, &verifier_index);

    // ------------------------------------------------------------------
    // 5. verify_with — verifies Kimchi/IOP polynomial commitments
    // ------------------------------------------------------------------
    let prover_proof = make_padded_proof_from_p2p(&proof).expect("padded proof");
    let result = verify_with(&verifier_index, &prover_proof, &public_inputs);

    let proof_valid = result.is_ok() && checks_ok;
    assert!(proof_valid, "Pickles proof invalid");

    sp1_zkvm::io::commit(&ZkappPublicValues { proof_valid });
}

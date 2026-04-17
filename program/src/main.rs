#![no_main]
sp1_zkvm::entrypoint!(main);

use ledger::{
    proofs::{
        prover::make_padded_proof_from_p2p,
        verification::{
            compute_deferred_values, get_message_for_next_step_proof,
            get_message_for_next_wrap_proof, get_prepared_statement, run_checks, verify_with, VK,
        },
        verifiers::make_zkapp_verifier_index,
    },
    scan_state::transaction_logic::{
        verifiable,
        zkapp_command::{verifiable::create, ZkAppCommand},
        TransactionStatus, WithStatus,
    },
    verifier::common::{check, CheckResult},
    VerificationKey, VerificationKeyWire,
};
use mina_p2p_messages::v2::{
    MinaBaseVerificationKeyWireStableV1, MinaBaseZkappCommandTStableV1WireStableV1,
    PicklesProofProofsVerified2ReprStableV2,
};
use zeko_sp1_lib::ZkappPublicValues;

pub fn main() {
    // ------------------------------------------------------------------
    // 1. Read inputs
    //    1. zkapp_command (wire)
    //    2. proof
    //    3. vk_wire
    // ------------------------------------------------------------------
    let zkapp_command: MinaBaseZkappCommandTStableV1WireStableV1 = sp1_zkvm::io::read();
    let proof: PicklesProofProofsVerified2ReprStableV2 = sp1_zkvm::io::read();
    let vk_wire: MinaBaseVerificationKeyWireStableV1 = sp1_zkvm::io::read();

    // ------------------------------------------------------------------
    // 2. Convert wire types
    // ------------------------------------------------------------------
    let vk: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime");
    let cmd: ZkAppCommand = (&zkapp_command)
        .try_into()
        .expect("wire -> runtime ZkAppCommand");

    // ------------------------------------------------------------------
    // 3. Build ZkappStatement — mirrors test_apply step 6
    // ------------------------------------------------------------------
    let cmd_verifiable = create(&cmd, false, |_, _| Ok(VerificationKeyWire::new(vk.clone())))
        .expect("verifiable::create");

    let (_vk_ret, zkapp_stmt, _proof_ret) = match check(WithStatus {
        data: verifiable::UserCommand::ZkAppCommand(Box::new(cmd_verifiable)),
        status: TransactionStatus::Applied,
    }) {
        CheckResult::ValidAssuming((_valid, mut xs)) => xs.pop().expect("empty"),
        other => panic!("expected ValidAssuming, got: {other:?}"),
    };

    // ------------------------------------------------------------------
    // 4. Pickles verification — exact mirror of test_apply step 6
    // ------------------------------------------------------------------
    let verifier_index = make_zkapp_verifier_index(&vk);
    let vk_wrapper = VK {
        commitments: *vk.wrap_index.clone(),
        index: &verifier_index,
        data: (),
    };

    let deferred_values = compute_deferred_values(&proof).expect("compute_deferred_values");
    let checks_ok = run_checks(&proof, vk_wrapper.index);

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

    let public_inputs = prepared
        .to_public_input(vk_wrapper.index.public)
        .expect("prepared -> public inputs");

    let prover_proof = make_padded_proof_from_p2p(&proof).expect("make_padded_proof");

    let proof_valid = match verify_with(vk_wrapper.index, &prover_proof, &public_inputs) {
        Ok(()) => checks_ok,
        Err(_) => false,
    };

    assert!(proof_valid, "Pickles proof invalid");

    // ------------------------------------------------------------------
    // 5. Commit public values
    // ------------------------------------------------------------------
    sp1_zkvm::io::commit(&ZkappPublicValues { proof_valid });
}

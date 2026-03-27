#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_ff::Zero;
use ledger::{
    proofs::verification::{
        compute_deferred_values, get_message_for_next_step_proof, get_message_for_next_wrap_proof,
        get_prepared_statement, run_checks, verify_with, VK,
    },
    proofs::{prover::make_padded_proof_from_p2p, verifiers::make_zkapp_verifier_index},
    scan_state::{
        currency::{Amount, Balance, Length, Slot},
        transaction_logic::{
            local_state::{apply_zkapp_command_first_pass, apply_zkapp_command_second_pass},
            protocol_state::{EpochData, EpochLedger, ProtocolStateView},
            zkapp_command::{verifiable::create, ZkAppCommand},
            TransactionStatus, WithStatus,
        },
    },
    verifier::common::{check, CheckResult},
    Account, AccountId, AuthRequired, BaseLedger, Mask, TokenId, VerificationKey,
    VerificationKeyWire, ZkAppAccount,
};
use mina_core::constants::constraint_constants;
use mina_curves::pasta::Fp;
use mina_p2p_messages::v2::{
    MinaBaseVerificationKeyWireStableV1, MinaBaseZkappCommandTStableV1WireStableV1,
    PicklesProofProofsVerified2ReprStableV2,
};
use zeko_sp1_lib::{AccountPrecondition, ZkappPublicValues};

pub fn main() {
    // ------------------------------------------------------------------
    // 1. Read inputs from stdin
    //    Order MUST match stdin.write() calls in script/src/main.rs
    // ------------------------------------------------------------------
    let zkapp_command: MinaBaseZkappCommandTStableV1WireStableV1 = sp1_zkvm::io::read();
    let proof: PicklesProofProofsVerified2ReprStableV2 = sp1_zkvm::io::read();
    let vk_wire: MinaBaseVerificationKeyWireStableV1 = sp1_zkvm::io::read();
    let precondition: AccountPrecondition = sp1_zkvm::io::read();

    // ------------------------------------------------------------------
    // 2. Convert wire types to runtime types
    // ------------------------------------------------------------------
    let verification_key: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime");

    let cmd: ZkAppCommand = (&zkapp_command)
        .try_into()
        .expect("wire -> runtime ZkAppCommand");

    // ------------------------------------------------------------------
    // 3. Build in-memory ledger from preconditions
    // ------------------------------------------------------------------
    let mut ledger = Mask::create(35);

    // --- Fee payer ---
    let fee_payer_id = AccountId::new(cmd.fee_payer.body.public_key.clone(), TokenId::default());
    let mut fee_payer_acct = Account::initialize(&fee_payer_id);
    fee_payer_acct.balance = Balance::from_u64(precondition.balance.unwrap_or(10_000_000_000));
    fee_payer_acct.nonce = cmd.fee_payer.body.nonce;
    ledger
        .get_or_create_account(fee_payer_id, fee_payer_acct)
        .expect("insert fee payer");

    // --- zkApp account ---
    let zkapp_update = &cmd.account_updates.0[0];
    let zkapp_id = AccountId::new(
        zkapp_update.elt.account_update.body.public_key.clone(),
        zkapp_update.elt.account_update.body.token_id.clone(),
    );

    let mut zkapp_acct = Account::initialize(&zkapp_id);
    zkapp_acct.balance = Balance::from_u64(precondition.balance.unwrap_or(10_000_000_000));

    // Proof authorization requires edit_state = Proof
    zkapp_acct.permissions.edit_state = AuthRequired::Proof;

    // Build zkApp state from precondition (None → Fp::zero())
    let mut zk = ZkAppAccount::default();
    zk.verification_key = Some(VerificationKeyWire::new(verification_key.clone()));
    for (i, slot) in precondition.state.iter().enumerate() {
        zk.app_state[i] = match slot {
            Some(bytes) => fp_from_bytes(bytes),
            None => Fp::zero(),
        };
    }
    zkapp_acct.zkapp = Some(Box::new(zk));

    ledger
        .get_or_create_account(zkapp_id, zkapp_acct)
        .expect("insert zkapp account");

    // --- All remaining referenced accounts ---
    for account_id in cmd.accounts_referenced() {
        if ledger.location_of_account(&account_id).is_some() {
            continue;
        }
        let mut acct = Account::initialize(&account_id);
        acct.balance = Balance::from_u64(precondition.balance.unwrap_or(10_000_000_000));
        ledger
            .get_or_create_account(account_id, acct)
            .expect("insert account");
    }

    let root_before = ledger.merkle_root();

    // ------------------------------------------------------------------
    // 4. Apply: first pass then second pass
    // ------------------------------------------------------------------
    let block_slot = 100u32;
    let state_view = minimal_state_view(block_slot);
    let global_slot = Slot::from_u32(block_slot);

    let partially_applied = apply_zkapp_command_first_pass(
        constraint_constants(),
        global_slot,
        &state_view,
        None,
        None,
        &mut ledger,
        &cmd,
    )
    .expect("first pass failed");

    let applied =
        apply_zkapp_command_second_pass(constraint_constants(), &mut ledger, partially_applied)
            .expect("second pass failed");

    let root_after = ledger.merkle_root();

    // ------------------------------------------------------------------
    // 5. Assert Applied
    // ------------------------------------------------------------------
    let transaction_applied = applied.command.status == TransactionStatus::Applied;
    assert!(
        transaction_applied,
        "transaction failed: {:?}",
        applied.command.status
    );

    // ------------------------------------------------------------------
    // 6. Pickles proof verification
    // ------------------------------------------------------------------
    let cmd_verifiable = create(&cmd, false, |_hash, _id| {
        Ok(VerificationKeyWire::new(verification_key.clone()))
    })
    .expect("verifiable::create");

    let with_status = WithStatus {
        data: ledger::scan_state::transaction_logic::verifiable::UserCommand::ZkAppCommand(
            Box::new(cmd_verifiable),
        ),
        status: TransactionStatus::Applied,
    };

    let (_vk_ret, zkapp_stmt, _proof_ret) = match check(with_status) {
        CheckResult::ValidAssuming((_valid, mut xs)) => xs.pop().expect("empty"),
        other => panic!("expected ValidAssuming, got: {other:?}"),
    };

    let verifier_index = make_zkapp_verifier_index(&verification_key);
    let vk = VK {
        commitments: *verification_key.wrap_index.clone(),
        index: &verifier_index,
        data: (),
    };

    let deferred_values = compute_deferred_values(&proof).expect("compute_deferred_values");
    let checks_ok = run_checks(&proof, vk.index);

    let msg_next_step = get_message_for_next_step_proof(
        &proof.statement.messages_for_next_step_proof,
        &vk.commitments,
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
        .to_public_input(vk.index.public)
        .expect("prepared -> public inputs");

    let prover_proof = make_padded_proof_from_p2p(&proof).expect("make_padded_proof");

    match verify_with(vk.index, &prover_proof, &public_inputs) {
        Ok(()) => assert!(checks_ok, "verify_with OK but run_checks failed"),
        Err(e) => panic!("invalid proof: {e:?}"),
    }

    // ------------------------------------------------------------------
    // 7. Commit public values → verifiable in Solidity
    // ------------------------------------------------------------------
    sp1_zkvm::io::commit(&ZkappPublicValues {
        precondition,
        state_root_before: fp_to_bytes(&root_before),
        state_root_after: fp_to_bytes(&root_after),
        tx_hash: compute_tx_hash(&zkapp_command),
        transaction_applied,
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn minimal_state_view(block_slot: u32) -> ProtocolStateView {
    let zero_epoch = EpochData {
        ledger: EpochLedger {
            hash: Fp::zero(),
            total_currency: Amount::zero(),
        },
        seed: Fp::zero(),
        start_checkpoint: Fp::zero(),
        lock_checkpoint: Fp::zero(),
        epoch_length: Length::from_u32(0),
    };

    ProtocolStateView {
        snarked_ledger_hash: Fp::zero(),
        blockchain_length: Length::from_u32(0),
        min_window_density: Length::from_u32(0),
        total_currency: Amount::zero(),
        global_slot_since_genesis: Slot::from_u32(block_slot),
        staking_epoch_data: zero_epoch.clone(),
        next_epoch_data: zero_epoch,
    }
}

/// Deserialize a little-endian [u8; 32] into Fp.
fn fp_from_bytes(bytes: &[u8; 32]) -> Fp {
    use ark_ff::PrimeField;
    Fp::from_le_bytes_mod_order(bytes)
}

/// Serialize Fp into a little-endian [u8; 32].
fn fp_to_bytes(fp: &Fp) -> [u8; 32] {
    use ark_serialize::CanonicalSerialize;
    let mut buf = [0u8; 32];
    fp.serialize_uncompressed(&mut buf[..])
        .expect("Fp serialize");
    buf
}

/// Minimal tx hash: SHA-256 of the bincode-serialized wire command.
fn compute_tx_hash(cmd: &MinaBaseZkappCommandTStableV1WireStableV1) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let bytes = bincode::serialize(cmd).expect("serialize tx");
    Sha256::digest(&bytes).into()
}

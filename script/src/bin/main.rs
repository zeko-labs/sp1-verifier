//! Zeko SP1 — zkApp proof verifier
//!
//! Execute (no proof):
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! Prove (core proof):
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use clap::Parser;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};
use std::time::Instant;
use zeko_sp1_lib::ZkappPublicValues;

#[path = "../parser.rs"]
mod parser;
use parser::parse_graphql_zkapp_file;

use ark_serialize::CanonicalSerialize;
use ledger::{
    proofs::verification::{
        compute_deferred_values, get_message_for_next_step_proof, get_message_for_next_wrap_proof,
        get_prepared_statement, VK,
    },
    proofs::verifiers::make_zkapp_verifier_index,
    scan_state::transaction_logic::{
        verifiable,
        zkapp_command::{verifiable::create, ZkAppCommand},
        TransactionStatus, WithStatus,
    },
    verifier::common::{check, CheckResult},
    VerificationKey, VerificationKeyWire,
};
use mina_curves::pasta::Fq;
use mina_p2p_messages::v2::MinaBaseVerificationKeyWireStableV1;

pub const ZKAPP_ELF: Elf = include_elf!("zkapp-program");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    prove: bool,
    #[arg(long, default_value = "proofs/graphql.txt")]
    graphql: String,
    #[arg(long, default_value = "proofs/vk.txt")]
    vk: String,
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();
    if args.execute == args.prove {
        eprintln!("Error: specify either --execute or --prove");
        std::process::exit(1);
    }

    // ------------------------------------------------------------------
    // 1. Parse
    // ------------------------------------------------------------------
    let vk_b64 =
        std::fs::read_to_string(&args.vk).unwrap_or_else(|e| panic!("read vk {}: {e}", args.vk));
    let parsed = parse_graphql_zkapp_file(&args.graphql)
        .unwrap_or_else(|e| panic!("parse graphql {}: {e}", args.graphql));

    let vk_wire =
        MinaBaseVerificationKeyWireStableV1::from_base64(vk_b64.trim()).expect("decode vk base64");
    let vk: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime");
    let cmd: ZkAppCommand = (&parsed.zkapp_command)
        .try_into()
        .expect("wire -> ZkAppCommand");

    eprintln!("✓ parsed");

    // ------------------------------------------------------------------
    // 2. Derive ZkappStatement
    // ------------------------------------------------------------------
    let cmd_verifiable = create(&cmd, false, |_, _| Ok(VerificationKeyWire::new(vk.clone())))
        .expect("verifiable::create");

    let (_, zkapp_stmt, _) = match check(WithStatus {
        data: verifiable::UserCommand::ZkAppCommand(Box::new(cmd_verifiable)),
        status: TransactionStatus::Applied,
    }) {
        CheckResult::ValidAssuming((_valid, mut xs)) => xs.pop().expect("empty"),
        other => panic!("expected ValidAssuming, got: {other:?}"),
    };

    eprintln!("✓ zkapp_stmt derived");

    // ------------------------------------------------------------------
    // 3. Derive public inputs on host
    // ------------------------------------------------------------------
    let proof = &parsed.proof;
    let verifier_index = make_zkapp_verifier_index(&vk);
    let vk_wrapper = VK {
        commitments: *vk.wrap_index.clone(),
        index: &verifier_index,
        data: (),
    };

    let deferred_values = compute_deferred_values(proof).expect("compute_deferred_values");

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

    let public_inputs_bytes: Vec<[u8; 32]> = public_inputs
        .iter()
        .map(|fq| {
            let mut buf = [0u8; 32];
            fq.serialize_uncompressed(&mut buf[..])
                .expect("serialize Fq");
            buf
        })
        .collect();

    eprintln!(
        "✓ public inputs derived ({} elements)",
        public_inputs_bytes.len()
    );

    // ------------------------------------------------------------------
    // 4. Write inputs to SP1 stdin
    //    1. vk_wire
    //    2. proof (raw)
    //    3. public_inputs_bytes
    // ------------------------------------------------------------------
    let mut stdin = SP1Stdin::new();
    stdin.write(&vk_wire);
    stdin.write(&parsed.proof);
    stdin.write(&public_inputs_bytes);

    let client = ProverClient::from_env();

    if args.execute {
        let (output, report) = client
            .execute(ZKAPP_ELF, stdin)
            .run()
            .expect("execution failed");

        println!("✓ Program executed successfully");
        println!("  cycles : {}", report.total_instruction_count());

        let public_values: ZkappPublicValues =
            bincode::deserialize(output.as_slice()).expect("decode public values");

        println!("  proof_valid: {}", public_values.proof_valid);
        assert!(public_values.proof_valid, "Kimchi proof invalid");
        println!("✅ Kimchi proof verified successfully");
    } else {
        let pk = client.setup(ZKAPP_ELF).expect("failed to setup ELF");

        println!("Generating proof...");
        let t = Instant::now();

        let proof = client.prove(&pk, stdin).run().expect("proof failed");

        println!("⏱  proving time: {:?}", t.elapsed());
        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("verify failed");

        let public_values: ZkappPublicValues =
            bincode::deserialize(proof.public_values.as_slice()).expect("decode public values");

        println!("  proof_valid: {}", public_values.proof_valid);
        assert!(public_values.proof_valid, "Kimchi proof invalid");

        std::fs::create_dir_all("proofs").expect("create proofs dir");
        proof.save("proofs/proof.bin").expect("save proof");
        println!("✓ Proof saved → proofs/proof.bin");
    }
}

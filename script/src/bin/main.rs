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

//! Zeko SP1 — zkApp proof verifier

use clap::Parser;
use kimchi::{circuits::constraints::FeatureFlags, linearization::expr_linearization};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};
use std::time::Instant;
use zeko_sp1_lib::ZkappPublicValues;

#[path = "../parser.rs"]
mod parser;
use parser::parse_graphql_zkapp_file;

use ark_poly::EvaluationDomain;
use ledger::{
    proofs::{transaction::endos, verifiers::make_zkapp_verifier_index},
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
    // 2. Derive ZkappStatement — reste sur le host (pas de crypto)
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
    // 3. Serialize zkapp_stmt — passé au guest pour validation crypto
    // ------------------------------------------------------------------
    let zkapp_stmt_bytes = bincode::serialize(&zkapp_stmt).expect("serialize zkapp_stmt");
    eprintln!("✓ zkapp_stmt: {} bytes", zkapp_stmt_bytes.len());

    // ------------------------------------------------------------------
    // 4. Serialize VerifierIndex (SRS excluded)
    // ------------------------------------------------------------------
    let feature_flags = FeatureFlags::default();
    let (linearization, powers_of_alpha) = expr_linearization(Some(&feature_flags), true);
    let (endo_q, _) = endos::<Fq>();

    let mut verifier_index = make_zkapp_verifier_index(&vk);
    verifier_index.linearization = linearization;
    verifier_index.powers_of_alpha = powers_of_alpha;
    verifier_index.endo = endo_q;

    let verifier_index_bytes =
        bincode::serialize(&verifier_index).expect("serialize verifier_index");

    eprintln!("✓ verifier_index: {} bytes", verifier_index_bytes.len());

    // ------------------------------------------------------------------
    // 5. Build stdin
    //    1. vk_wire        → write
    //    2. proof          → write
    //    3. zkapp_stmt     → write_slice (raw bincode)
    //    4. verifier_index → write_slice (raw bincode)
    // ------------------------------------------------------------------
    let mut stdin = SP1Stdin::new();
    stdin.write(&vk_wire);
    stdin.write(&parsed.proof);
    stdin.write_slice(&zkapp_stmt_bytes);
    stdin.write_slice(&verifier_index_bytes);

    let client = ProverClient::from_env();

    if args.execute {
        let (output, report) = client
            .execute(ZKAPP_ELF, stdin)
            .run()
            .expect("execution failed");

        println!("✓ Program executed successfully");
        println!("  cycles   : {}", report.total_instruction_count());
        println!("  total gas: {:?}", report.gas());
        for (name, cycles) in &report.cycle_tracker {
            println!("  [{name}] cycles: {cycles}");
        }

        let public_values: ZkappPublicValues =
            bincode::deserialize(output.as_slice()).expect("decode public values");

        println!("  proof_valid: {}", public_values.proof_valid);
        println!("  vk_hash: 0x{}", hex::encode(public_values.vk_hash));
        for (i, s) in public_values.app_state.iter().enumerate() {
            println!("  app_state[{}]: 0x{}", i, hex::encode(s));
        }

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
        println!("  vk_hash: 0x{}", hex::encode(public_values.vk_hash));
        for (i, s) in public_values.app_state.iter().enumerate() {
            println!("  app_state[{}]: 0x{}", i, hex::encode(s));
        }

        assert!(public_values.proof_valid, "Kimchi proof invalid");
        std::fs::create_dir_all("proofs").expect("create proofs dir");
        proof.save("proofs/proof.bin").expect("save proof");
        println!("✓ Proof saved → proofs/proof.bin");
    }
}

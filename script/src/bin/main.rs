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

mod parser;

use clap::Parser;
use parser::parse_graphql_zkapp_file;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, SP1Stdin,
};
use std::time::Instant;
use zeko_sp1_lib::{AccountPrecondition, ZkappPublicValues};

/// The ELF of the guest program — name must match program/Cargo.toml `name`.
pub const ZKAPP_ELF: Elf = include_elf!("zeko-sp1-program");

/// CLI arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Execute the program without generating a proof
    #[arg(long)]
    execute: bool,

    /// Generate a core proof
    #[arg(long)]
    prove: bool,

    /// Path to the GraphQL mutation file
    #[arg(long, default_value = "proofs/graphql.txt")]
    graphql: String,

    /// Path to the base64-encoded verification key
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
    // 1. Parse — host only, never runs in the zkVM
    // ------------------------------------------------------------------
    let vk_b64 =
        std::fs::read_to_string(&args.vk).unwrap_or_else(|e| panic!("read vk {}: {e}", args.vk));

    let parsed = parse_graphql_zkapp_file(&args.graphql)
        .unwrap_or_else(|e| panic!("parse graphql {}: {e}", args.graphql));

    let vk_wire =
        mina_p2p_messages::v2::MinaBaseVerificationKeyWireStableV1::from_base64(vk_b64.trim())
            .expect("decode vk base64");

    // ------------------------------------------------------------------
    // 2. Build account precondition
    //    In production this comes from Solidity contract calldata.
    // ------------------------------------------------------------------
    let mut precondition = AccountPrecondition::default();

    // state[0] = Fp(0) — mirrors the precondition in the test transaction
    precondition.state[0] = Some([0u8; 32]);
    precondition.balance = Some(10_000_000_000); // 10 MINA in nanomina

    // ------------------------------------------------------------------
    // 3. Write inputs to SP1 stdin
    //    Order MUST match sp1_zkvm::io::read() calls in program/src/main.rs
    //    1. zkapp_command
    //    2. proof
    //    3. vk_wire
    //    4. precondition
    // ------------------------------------------------------------------
    let mut stdin = SP1Stdin::new();
    stdin.write(&parsed.zkapp_command);
    stdin.write(&parsed.proof);
    stdin.write(&vk_wire);
    stdin.write(&precondition);

    let client = ProverClient::from_env();

    if args.execute {
        // ------------------------------------------------------------------
        // Execute — no proof, fast feedback loop
        // ------------------------------------------------------------------
        let (output, report) = client
            .execute(ZKAPP_ELF, stdin)
            .run()
            .expect("execution failed");

        println!("✓ Program executed successfully");
        println!("  cycles : {}", report.total_instruction_count());
        println!("  gas    : {:?}", report.gas());

        // Decode committed public values
        let public_values: ZkappPublicValues =
            bincode::deserialize(output.as_slice()).expect("decode public values");

        print_public_values(&public_values);
        assert!(
            public_values.transaction_applied,
            "transaction was not Applied"
        );
        println!("✅ Transaction applied successfully");
    } else {
        // ------------------------------------------------------------------
        // Prove — core proof (no Groth16 for now)
        // ------------------------------------------------------------------
        let pk = client.setup(ZKAPP_ELF).expect("failed to setup ELF");

        println!("Generating proof...");
        let t = Instant::now();

        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        println!("⏱  proving time: {:?}", t.elapsed());
        println!("✓ Proof generated");

        // Verify locally
        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("failed to verify proof");
        println!("✓ Proof verified");

        // Decode committed public values
        let public_values: ZkappPublicValues =
            bincode::deserialize(proof.public_values.as_slice()).expect("decode public values");

        print_public_values(&public_values);
        assert!(
            public_values.transaction_applied,
            "transaction was not Applied"
        );
        println!("✅ Transaction applied successfully");

        // Save proof
        std::fs::create_dir_all("proofs").expect("create proofs dir");
        proof.save("proofs/proof.bin").expect("save proof");
        println!("✓ Proof saved → proofs/proof.bin");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn print_public_values(pv: &ZkappPublicValues) {
    println!("Public values:");
    println!(
        "  state_root_before  : {}",
        hex::encode(pv.state_root_before)
    );
    println!(
        "  state_root_after   : {}",
        hex::encode(pv.state_root_after)
    );
    println!("  tx_hash            : {}", hex::encode(pv.tx_hash));
    println!("  transaction_applied: {}", pv.transaction_applied);
}

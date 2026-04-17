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
    // 1. Parse — host only
    // ------------------------------------------------------------------
    let vk_b64 =
        std::fs::read_to_string(&args.vk).unwrap_or_else(|e| panic!("read vk {}: {e}", args.vk));

    let parsed = parse_graphql_zkapp_file(&args.graphql)
        .unwrap_or_else(|e| panic!("parse graphql {}: {e}", args.graphql));

    let vk_wire =
        MinaBaseVerificationKeyWireStableV1::from_base64(vk_b64.trim()).expect("decode vk base64");

    eprintln!("✓ parsed");

    // ------------------------------------------------------------------
    // 2. Write inputs to SP1 stdin
    //    Order MUST match sp1_zkvm::io::read() calls in program/src/main.rs
    //    1. zkapp_command
    //    2. proof
    //    3. vk_wire
    // ------------------------------------------------------------------
    let mut stdin = SP1Stdin::new();
    stdin.write(&parsed.zkapp_command);
    stdin.write(&parsed.proof);
    stdin.write(&vk_wire);

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
        assert!(public_values.proof_valid, "Pickles proof invalid");
        println!("✅ zkApp proof verified successfully");
    } else {
        let pk = client.setup(ZKAPP_ELF).expect("failed to setup ELF");

        println!("Generating proof...");
        let t = Instant::now();

        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        println!("⏱  proving time: {:?}", t.elapsed());

        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("failed to verify proof");
        println!("✓ Proof verified");

        let public_values: ZkappPublicValues =
            bincode::deserialize(proof.public_values.as_slice()).expect("decode public values");

        println!("  proof_valid: {}", public_values.proof_valid);
        assert!(public_values.proof_valid, "Pickles proof invalid");

        std::fs::create_dir_all("proofs").expect("create proofs dir");
        proof.save("proofs/proof.bin").expect("save proof");
        println!("✓ Proof saved → proofs/proof.bin");
    }
}

//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_primitives::U256;
use clap::Parser;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};
use std::time::Instant;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: Elf = include_elf!("fibonacci-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    /// Input a (u64)
    #[arg(long, default_value_t = 3412)]
    a: u64,

    /// Input b (u64)
    #[arg(long, default_value_t = 548748548)]
    b: u64,

    /// Expected result (base 10) pour assert
    #[arg(long)]
    expected: Option<String>,
}

fn main() {
    // Logger + dotenv (comme l'exemple)
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Prover client (supporte SP1_PROVER=cpu/cuda, etc.)
    let client = ProverClient::from_env();

    let a: u64 = 3412;
    let b: u64 = 548748548;

    // Inputs
    let mut stdin = SP1Stdin::new();
    stdin.write(&a);
    stdin.write(&b);

    println!("a: {}", args.a);
    println!("b: {}", args.b);

    // Parse expected
    let exp = U256::from_str_radix(
        "24245350037390325723675562428846509781869515058976947458013661211417354108422",
        10,
    )
    .unwrap();

    if args.execute {
        // Execute (mo proof)
        let (output, report) = client.execute(FIBONACCI_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");

        //  Decode public output (commit) -> U256
        let bytes: [u8; 32] = output.as_slice().try_into().unwrap();
        let result = U256::from_be_bytes(bytes);

        println!("Result: {:?}", result);

        assert_eq!(result, exp, "hash mismatch (execute)");
        println!("✅ Output matches expected");

        println!("Number of cycles: {}", report.total_instruction_count());
        println!("gas: {:?}", report.gas());
    } else {
        // Prove
        let pk = client.setup(FIBONACCI_ELF).expect("failed to setup elf");

        let t_prove = Instant::now();
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");
        let prove_dt = t_prove.elapsed();
        println!("⏱ proving time: {:?}", prove_dt);

        println!("Successfully generated proof!");

        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("failed to verify proof");
        println!("Successfully verified proof!");

        // 🔓 Decode committed public values from the proof
        let bytes: [u8; 32] = proof.public_values.as_slice().try_into().unwrap();
        let result = U256::from_be_bytes(bytes);

        println!("Result (from proof public values): {:?}", result);

        assert_eq!(result, exp, "hash mismatch (prove)");
        println!("✅ Output matches expected");
    }
}

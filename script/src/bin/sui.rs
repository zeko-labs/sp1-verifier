//! Generate SP1 Groth16 proof and convert to Sui format.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release --bin sui
//! ```

use alloy_primitives::U256;
use clap::Parser;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use sp1_sui::convert_sp1_gnark_to_ark;
use std::path::PathBuf;
use std::time::Instant;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

/// Expected result for verification
const EXPECTED_RESULT: &str =
    "24245350037390325723675562428846509781869515058976947458013661211417354108422";

/// The arguments for the Sui command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct SuiArgs {
    /// Input a (u64)
    #[arg(long, default_value_t = 3412)]
    a: u64,

    /// Input b (u64)
    #[arg(long, default_value_t = 548748548)]
    b: u64,
}

/// A fixture for Sui Move contract verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1SuiProofFixture {
    a: u64,
    b: u64,
    result: String,
    vkey: String,
    public_values: String,
    // Sui-specific format (ark-bn254 serialization)
    pvk_bytes: String,
    public_inputs_bytes: String,
    proof_points_bytes: String,
}

fn main() {
    // Setup logger
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse arguments
    let args = SuiArgs::parse();

    // Setup prover client
    let client = ProverClient::from_env();

    // Setup the program
    let t_setup = Instant::now();
    let (pk, vk) = client.setup(FIBONACCI_ELF);
    println!("⏱ Setup time: {:?}", t_setup.elapsed());

    // Setup inputs
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.a);
    stdin.write(&args.b);

    println!("a: {}", args.a);
    println!("b: {}", args.b);
    println!("Generating Groth16 proof for Sui...");

    // Generate Groth16 proof (required for Sui)
    let t_prove = Instant::now();
    let proof = client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .expect("failed to generate proof");
    println!("⏱ Proving time: {:?}", t_prove.elapsed());

    // Verify the proof
    client.verify(&proof, &vk).expect("failed to verify proof");
    println!("✅ Proof verified successfully!");

    // Decode and verify result
    let bytes = proof.public_values.as_slice();
    let result_bytes: [u8; 32] = bytes.try_into().expect("public values should be 32 bytes");
    let result = U256::from_be_bytes(result_bytes);

    // Expected value
    let expected = U256::from_str_radix(EXPECTED_RESULT, 10).unwrap();

    println!("\n=== Result Verification ===");
    println!("Result:   {}", result);
    println!("Expected: {}", expected);

    assert_eq!(result, expected, "❌ Result mismatch!");
    println!("✅ Result matches expected value!");

    // Save binary proof for potential later use
    let proofs_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../proofs");
    std::fs::create_dir_all(&proofs_path).expect("failed to create proofs path");
    proof
        .save(proofs_path.join("poseidon_proof.bin"))
        .expect("failed to save proof");
    println!("✅ Saved binary proof to proofs/poseidon_proof.bin");

    // Create fixture with Sui format
    create_sui_fixture(&proof, &vk, args.a, args.b, result);
}

fn create_sui_fixture(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    a: u64,
    b: u64,
    result: U256,
) {
    let bytes = proof.public_values.as_slice();

    println!("\n========================================");
    println!("=== SP1 -> Sui Conversion ===");
    println!("========================================");

    // Convert SP1 Groth16 proof to Sui/Ark format
    let t_convert = Instant::now();
    let (pvk, public_inputs, proof_points) = convert_sp1_gnark_to_ark(proof.clone());
    println!("⏱ Conversion time: {:?}", t_convert.elapsed());

    println!("\n=== Sui Format Sizes ===");
    println!("PVK bytes: {} bytes", pvk.len());
    println!("Public inputs bytes: {} bytes", public_inputs.len());
    println!("Proof points bytes: {} bytes", proof_points.len());

    // Create fixture
    let fixture = SP1SuiProofFixture {
        a,
        b,
        result: format!("{}", result),
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(bytes)),
        pvk_bytes: format!("0x{}", hex::encode(&pvk)),
        public_inputs_bytes: format!("0x{}", hex::encode(&public_inputs)),
        proof_points_bytes: format!("0x{}", hex::encode(&proof_points)),
    };

    println!("\n=== Verification Data ===");
    println!("Result (U256): {}", fixture.result);
    println!("VKey: {}", fixture.vkey);
    println!("Public Values: {}", fixture.public_values);

    println!("\n=== Sui Move Input (hex) ===");
    println!("pvk_bytes: {}", fixture.pvk_bytes);
    println!("public_inputs_bytes: {}", fixture.public_inputs_bytes);
    println!("proof_points_bytes: {}", fixture.proof_points_bytes);

    // Estimate Sui gas cost (approximate)
    // Groth16 verification on Sui costs ~5000-10000 gas units
    let estimated_gas = 10_000u64;
    let gas_price = 1000u64; // MIST per gas unit (approximate)
    let estimated_cost_mist = estimated_gas * gas_price;
    let estimated_cost_sui = estimated_cost_mist as f64 / 1_000_000_000.0;

    println!("\n=== Estimated Sui Gas Cost ===");
    println!("Gas units: ~{}", estimated_gas);
    println!(
        "Cost: ~{} SUI (~{} MIST)",
        estimated_cost_sui, estimated_cost_mist
    );
    println!("Note: Actual cost depends on network conditions");

    // Save fixture
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join("sui-groth16-fixture.json"),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");

    println!("\n✅ Saved Sui fixture to contracts/src/fixtures/sui-groth16-fixture.json");
    println!("========================================");
}

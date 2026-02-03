//! Estimate real gas cost on Sui testnet via dry-run
//!
//! Usage:
//! ```shell
//! cargo run --release --bin sui_gas -- --package 0xf5d60348e4c02e3a284866305c51df2a440879d10fdecfbb80dc4b99fe12a16c
//! ```

use clap::Parser;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Deployed package ID on Sui testnet
    #[arg(long)]
    package: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1SuiProofFixture {
    pvk_bytes: String,
    public_inputs_bytes: String,
    proof_points_bytes: String,
}

fn main() {
    let args = Args::parse();

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../contracts/src/fixtures/sui-groth16-fixture.json");

    let fixture_json = fs::read_to_string(&fixture_path)
        .expect("Failed to read fixture. Run 'cargo run --release --bin sui' first.");

    let fixture: SP1SuiProofFixture = serde_json::from_str(&fixture_json).unwrap();

    println!("=== Sui Gas Estimation (Dry Run) ===");
    println!("Package: {}", args.package);

    // Build the sui client call command
    let output = Command::new("sui")
        .args([
            "client",
            "call",
            "--package",
            &args.package,
            "--module",
            "verifier",
            "--function",
            "verify_poseidon_proof",
            "--args",
            &fixture.pvk_bytes,
            &fixture.public_inputs_bytes,
            &fixture.proof_points_bytes,
            "--gas-budget",
            "100000000",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("Failed to execute sui client call");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        eprintln!("Error: {}", stderr);
        std::process::exit(1);
    }

    println!("\n{}", stdout);

    // Parse JSON output to extract gas
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(effects) = json.get("effects") {
            if let Some(gas) = effects.get("gasUsed") {
                println!("\n=== Gas Breakdown ===");
                println!(
                    "Computation: {} MIST",
                    gas.get("computationCost")
                        .unwrap_or(&serde_json::Value::Null)
                );
                println!(
                    "Storage: {} MIST",
                    gas.get("storageCost").unwrap_or(&serde_json::Value::Null)
                );
                println!(
                    "Rebate: {} MIST",
                    gas.get("storageRebate").unwrap_or(&serde_json::Value::Null)
                );

                let computation = gas
                    .get("computationCost")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let storage = gas
                    .get("storageCost")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let rebate = gas
                    .get("storageRebate")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);

                let total = computation + storage - rebate;
                let total_sui = total as f64 / 1_000_000_000.0;

                println!("\nTotal: {} MIST ({:.9} SUI)", total, total_sui);
            }
        }
    }
}

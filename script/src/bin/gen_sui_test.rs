//! Generate Move test file with actual proof data
//!
//! Run after generating the proof:
//! ```shell
//! cargo run --release --bin gen_sui_test
//! ```

use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1SuiProofFixture {
    a: u64,
    b: u64,
    result: String,
    vkey: String,
    public_values: String,
    pvk_bytes: String,
    public_inputs_bytes: String,
    proof_points_bytes: String,
}

fn main() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../contracts/src/fixtures/sui-groth16-fixture.json");

    let fixture_json = fs::read_to_string(&fixture_path).expect(
        "Failed to read sui-groth16-fixture.json. Run 'cargo run --release --bin sui' first.",
    );

    let fixture: SP1SuiProofFixture =
        serde_json::from_str(&fixture_json).expect("Failed to parse fixture JSON");

    // Remove 0x prefix for Move hex literals
    let pvk = fixture.pvk_bytes.trim_start_matches("0x");
    let public_inputs = fixture.public_inputs_bytes.trim_start_matches("0x");
    let proof_points = fixture.proof_points_bytes.trim_start_matches("0x");

    let test_code = format!(
        r##"#[test_only]
module poseidon_mina::verifier_tests {{
    use poseidon_mina::verifier;

    // Generated test data for Poseidon hash verification
    // a: {}
    // b: {}
    // Expected result: {}

    #[test]
    fun test_verify_valid_proof() {{
        let pvk_bytes = x"{}";
        let public_inputs_bytes = x"{}";
        let proof_points_bytes = x"{}";

        let is_valid = verifier::verify_poseidon_proof(
            pvk_bytes,
            public_inputs_bytes,
            proof_points_bytes
        );

        assert!(is_valid, 0);
    }}

    #[test]
    fun test_verify_invalid_proof_fails() {{
        let pvk_bytes = x"{}";
        let public_inputs_bytes = x"{}";
        // Corrupted proof (all zeros)
        let proof_points_bytes = x"0000000000000000000000000000000000000000000000000000000000000000";

        let is_valid = verifier::verify_poseidon_proof(
            pvk_bytes,
            public_inputs_bytes,
            proof_points_bytes
        );

        assert!(!is_valid, 1);
    }}
}}
"##,
        fixture.a, fixture.b, fixture.result, pvk, public_inputs, proof_points, pvk, public_inputs
    );

    let test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../sui-contracts/tests/verifier_tests.move");

    fs::create_dir_all(test_path.parent().unwrap()).expect("Failed to create tests directory");
    fs::write(&test_path, test_code).expect("Failed to write test file");

    println!("✅ Generated Move test file: {}", test_path.display());
    println!();
    println!("To run the test:");
    println!("  cd sui-contracts");
    println!("  sui move test --gas-limit 10000000000");
}

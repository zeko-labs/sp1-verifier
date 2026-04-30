//! Zeko SP1 — EVM-compatible zkApp proof verifier
//!
//! Generate an EVM-compatible proof with the Succinct Prover Network:
//! ```shell
//! export NETWORK_PRIVATE_KEY=...
//! RUST_LOG=info cargo run --release --bin evm -- --system groth16
//! ```
//! or
//! ```shell
//! export NETWORK_PRIVATE_KEY=...
//! RUST_LOG=info cargo run --release --bin evm -- --system plonk
//! ```

use ark_serialize::CanonicalSerialize;
use clap::{Parser, ValueEnum};
use kimchi::{circuits::constraints::FeatureFlags, linearization::expr_linearization};
use mina_curves::pasta::Fq;
use mina_p2p_messages::v2::{
    MinaBaseVerificationKeyWireStableV1, PicklesBaseProofsVerifiedStableV1,
};
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, network::NetworkMode, utils, Elf, HashableKey, ProveRequest, Prover, ProverClient,
    ProvingKey, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use std::path::PathBuf;
use std::time::Instant;
use zeko_sp1_lib::{SerializableDeferredValues, SerializablePlonk, ZkappPublicValues};

#[path = "../parser.rs"]
mod parser;
use parser::parse_graphql_zkapp_file;

use ledger::{
    proofs::{
        transaction::endos, verification::compute_deferred_values,
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

/// The ELF for the zkApp SP1 program.
pub const ZKAPP_ELF: Elf = include_elf!("zkapp-program");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct EVMArgs {
    #[arg(long, default_value = "proofs/graphql.txt")]
    graphql: String,

    #[arg(long, default_value = "proofs/vk.txt")]
    vk: String,

    #[arg(long, value_enum, default_value = "groth16")]
    system: ProofSystem,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Plonk,
    Groth16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1ProofFixture {
    system: String,
    graphql_path: String,
    vk_path: String,
    proof_valid: bool,
    zkapp_command_bytes_len: usize,
    zkapp_stmt_bytes_len: usize,
    deferred_values_bytes_len: usize,
    verifier_index_bytes_len: usize,
    vkey: String,
    public_values: String,
    proof: String,
}

#[tokio::main]
async fn main() {
    utils::setup_logger();
    dotenv::dotenv().ok();

    let args = EVMArgs::parse();

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

    let zkapp_cmd_bytes =
        bincode::serialize(&parsed.zkapp_command).expect("serialize zkapp_command wire");
    eprintln!("✓ zkapp_command: {} bytes", zkapp_cmd_bytes.len());

    // ------------------------------------------------------------------
    // 2. Derive ZkappStatement on the host
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
    // 3. Serialize ZkappStatement
    // ------------------------------------------------------------------
    let zkapp_stmt_bytes = bincode::serialize(&zkapp_stmt).expect("serialize zkapp_stmt");
    eprintln!("✓ zkapp_stmt: {} bytes", zkapp_stmt_bytes.len());

    fn fp_to_bytes(fp: mina_curves::pasta::Fp) -> [u8; 32] {
        let mut buf: [u8; 32] = [0u8; 32];
        fp.serialize_uncompressed(&mut buf[..]).unwrap();
        buf
    }

    let dv = compute_deferred_values(&parsed.proof).expect("compute_deferred_values");

    let serializable_dv = SerializableDeferredValues {
        plonk: SerializablePlonk {
            alpha: dv.plonk.alpha,
            beta: dv.plonk.beta,
            gamma: dv.plonk.gamma,
            zeta: dv.plonk.zeta,
            zeta_to_srs_length: fp_to_bytes(dv.plonk.zeta_to_srs_length.shifted),
            zeta_to_domain_size: fp_to_bytes(dv.plonk.zeta_to_domain_size.shifted),
            perm: fp_to_bytes(dv.plonk.perm.shifted),
            lookup: dv.plonk.lookup,
            feature_flags_range_check0: dv.plonk.feature_flags.range_check0,
            feature_flags_range_check1: dv.plonk.feature_flags.range_check1,
            feature_flags_foreign_field_add: dv.plonk.feature_flags.foreign_field_add,
            feature_flags_foreign_field_mul: dv.plonk.feature_flags.foreign_field_mul,
            feature_flags_xor: dv.plonk.feature_flags.xor,
            feature_flags_rot: dv.plonk.feature_flags.rot,
            feature_flags_lookup: dv.plonk.feature_flags.lookup,
            feature_flags_runtime_tables: dv.plonk.feature_flags.runtime_tables,
        },
        combined_inner_product: fp_to_bytes(dv.combined_inner_product.shifted),
        b: fp_to_bytes(dv.b.shifted),
        xi: dv.xi,
        bulletproof_challenges: dv
            .bulletproof_challenges
            .iter()
            .map(|fp| fp_to_bytes(*fp))
            .collect(),
        branch_data_proofs_verified: match dv.branch_data.proofs_verified {
            PicklesBaseProofsVerifiedStableV1::N0 => 0,
            PicklesBaseProofsVerifiedStableV1::N1 => 1,
            PicklesBaseProofsVerifiedStableV1::N2 => 2,
        },
        branch_data_domain_log2: dv.branch_data.domain_log2.0.into(),
    };

    let deferred_values_bytes =
        bincode::serialize(&serializable_dv).expect("serialize deferred_values");
    eprintln!("✓ deferred_values: {} bytes", deferred_values_bytes.len());

    // ------------------------------------------------------------------
    // 4. Serialize VerifierIndex without SRS
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
    // 5. Build stdin exactly like the regular main
    // ------------------------------------------------------------------
    let mut stdin = SP1Stdin::new();
    stdin.write(&vk_wire);
    stdin.write(&parsed.proof);
    stdin.write_slice(&zkapp_stmt_bytes);
    stdin.write_slice(&deferred_values_bytes);
    stdin.write_slice(&zkapp_cmd_bytes);
    stdin.write_slice(&verifier_index_bytes);

    // ------------------------------------------------------------------
    // 6. Setup and prove on the Succinct Prover Network
    // ------------------------------------------------------------------
    let client = ProverClient::builder()
        .network_for(NetworkMode::Mainnet)
        .build()
        .await;

    let t_setup = Instant::now();
    let pk = client.setup(ZKAPP_ELF).await.expect("failed to setup ELF");
    println!("⏱ Setup time: {:?}", t_setup.elapsed());
    println!("Proof System: {:?}", args.system);

    println!("Generating EVM-compatible proof on Succinct Prover Network...");
    let t_prove = Instant::now();

    let proof = match args.system {
        ProofSystem::Plonk => client.prove(&pk, stdin).plonk().await,
        ProofSystem::Groth16 => client.prove(&pk, stdin).groth16().await,
    }
    .expect("failed to generate proof");

    println!("⏱ Proving time: {:?}", t_prove.elapsed());

    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("verify failed");

    create_proof_fixture(
        &proof,
        pk.verifying_key(),
        &args.graphql,
        &args.vk,
        zkapp_cmd_bytes.len(),
        zkapp_stmt_bytes.len(),
        deferred_values_bytes.len(),
        verifier_index_bytes.len(),
        args.system,
    );
}

fn create_proof_fixture(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    graphql_path: &str,
    vk_path: &str,
    zkapp_command_bytes_len: usize,
    zkapp_stmt_bytes_len: usize,
    deferred_values_bytes_len: usize,
    verifier_index_bytes_len: usize,
    system: ProofSystem,
) {
    let public_values: ZkappPublicValues =
        bincode::deserialize(proof.public_values.as_slice()).expect("decode public values");

    println!("  proof_valid: {}", public_values.proof_valid);
    println!("  vk_hash: 0x{}", hex::encode(public_values.vk_hash));

    for (i, s) in public_values.state_before.iter().enumerate() {
        println!("  state_before[{}]: 0x{}", i, hex::encode(s));
    }

    for (i, s) in public_values.state_after.iter().enumerate() {
        println!("  state_after[{}]: 0x{}", i, hex::encode(s));
    }

    println!(
        "  action_state_before: 0x{}",
        hex::encode(public_values.action_state_before)
    );

    assert!(public_values.proof_valid, "Kimchi proof invalid");
    println!("✅ Kimchi proof verified successfully");

    let fixture = SP1ProofFixture {
        system: format!("{:?}", system).to_lowercase(),
        graphql_path: graphql_path.to_owned(),
        vk_path: vk_path.to_owned(),
        proof_valid: public_values.proof_valid,
        zkapp_command_bytes_len,
        zkapp_stmt_bytes_len,
        deferred_values_bytes_len,
        verifier_index_bytes_len,
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(proof.public_values.as_slice())),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    println!("Verification Key: {}", fixture.vkey);
    println!("Public Values: {}", fixture.public_values);
    println!("Proof Bytes: {}", fixture.proof);

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join(format!("{:?}-fixture.json", system).to_lowercase()),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");

    std::fs::create_dir_all("proofs").expect("create proofs dir");
    proof.save("proofs/evm-proof.bin").expect("save proof");
    println!("✓ Proof saved → proofs/evm-proof.bin");
}

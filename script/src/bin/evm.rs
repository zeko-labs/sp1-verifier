//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can have an
//! EVM-Compatible proof generated which can be verified on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system groth16
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release --bin evm -- --system plonk
//! ```

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use sp1_sdk::blocking::ProveRequest;
use sp1_sdk::{
    blocking::{Prover, ProverClient},
    include_elf, Elf, HashableKey, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};
use std::path::PathBuf;
use std::time::Instant;
use zeko_sp1_lib::ZkappPublicValues;

#[path = "../parser.rs"]
mod parser;
use parser::parse_graphql_zkapp_file;

use ark_poly::EvaluationDomain;
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
    verifier_index_bytes_len: usize,
    public_inputs_bytes_len: usize,
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = EVMArgs::parse();

    // ------------------------------------------------------------------
    // 1. Parse host inputs
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
    // 2. Derive zkApp statement
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
    let domain_size = verifier_index.domain.size();
    eprintln!("✓ domain_size: {}", domain_size);

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
    // 4. Serialize verifier index and public inputs
    // ------------------------------------------------------------------
    let verifier_index_bytes =
        bincode::serialize(&verifier_index).expect("serialize verifier_index");
    let public_inputs_serialized =
        bincode::serialize(&public_inputs_bytes).expect("serialize public inputs");

    eprintln!("✓ verifier_index: {} bytes", verifier_index_bytes.len());
    eprintln!("✓ public_inputs:  {} bytes", public_inputs_serialized.len());

    // ------------------------------------------------------------------
    // 5. Write SP1 stdin exactly like the regular main
    // ------------------------------------------------------------------
    let mut stdin = SP1Stdin::new();
    stdin.write(&vk_wire);
    stdin.write(&parsed.proof);
    stdin.write_slice(&public_inputs_serialized);
    stdin.write_slice(&verifier_index_bytes);

    // ------------------------------------------------------------------
    // 6. Setup and prove with an EVM-compatible proof system
    // ------------------------------------------------------------------
    let client = ProverClient::from_env();

    let t_setup = Instant::now();
    let pk = client.setup(ZKAPP_ELF).expect("failed to setup ELF");
    println!("⏱ Setup time: {:?}", t_setup.elapsed());
    println!("Proof System: {:?}", args.system);

    let t_prove = Instant::now();
    let proof = match args.system {
        ProofSystem::Plonk => client.prove(&pk, stdin).plonk().run(),
        ProofSystem::Groth16 => client.prove(&pk, stdin).groth16().run(),
    }
    .expect("failed to generate proof");
    println!("⏱ Proving time: {:?}", t_prove.elapsed());

    create_proof_fixture(
        &proof,
        pk.verifying_key(),
        &args.graphql,
        &args.vk,
        verifier_index_bytes.len(),
        public_inputs_serialized.len(),
        args.system,
    );
}

fn create_proof_fixture(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    graphql_path: &str,
    vk_path: &str,
    verifier_index_bytes_len: usize,
    public_inputs_bytes_len: usize,
    system: ProofSystem,
) {
    let public_values: ZkappPublicValues =
        bincode::deserialize(proof.public_values.as_slice()).expect("decode public values");

    let fixture = SP1ProofFixture {
        system: format!("{:?}", system).to_lowercase(),
        graphql_path: graphql_path.to_owned(),
        vk_path: vk_path.to_owned(),
        proof_valid: public_values.proof_valid,
        verifier_index_bytes_len,
        public_inputs_bytes_len,
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(proof.public_values.as_slice())),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    println!("Verification Key: {}", fixture.vkey);
    println!("Public Values: {}", fixture.public_values);
    println!("proof_valid: {}", fixture.proof_valid);
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

// ---------------------------------------------------------------------------
// parser.rs — host-only parsing helpers
// Ported verbatim from verification-test/src/lib.rs.
// None of this code runs inside the SP1 guest (zkVM).
// ---------------------------------------------------------------------------

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use juniper::{execute_sync, graphql_object, EmptySubscription, FieldResult, RootNode, Variables};
use mina_node_native::graphql::zkapp::{GraphQLSendZkappResponse, SendZkappInput};
use mina_p2p_messages::v2::{
    MinaBaseControlStableV2, MinaBaseUserCommandStableV2,
    MinaBaseZkappCommandTStableV1WireStableV1, PicklesProofProofsVerified2ReprStableV2,
};
use rsexp::{OfSexp, Sexp};
use serde::Deserialize;
use std::sync::Mutex;
use zeko_sp1_lib::ParsedZkappTransaction;

// ---------------------------------------------------------------------------
// Juniper schema — minimal, only used to parse GraphQL mutation syntax
// ---------------------------------------------------------------------------

struct Context {
    result: Mutex<Option<MinaBaseUserCommandStableV2>>,
}
impl juniper::Context for Context {}

struct Query;
#[graphql_object]
#[graphql(context = Context)]
impl Query {
    fn dummy() -> bool {
        true
    }
}

struct Mutation;
#[graphql_object]
#[graphql(context = Context)]
impl Mutation {
    fn send_zkapp(
        context: &Context,
        input: SendZkappInput,
    ) -> FieldResult<GraphQLSendZkappResponse> {
        let wire: MinaBaseUserCommandStableV2 = input.try_into()?;
        *context.result.lock().unwrap() = Some(wire.clone());
        let response = GraphQLSendZkappResponse::try_from(wire)?;
        Ok(response)
    }
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Parse a GraphQL `sendZkapp` mutation string and extract the wire
/// transaction, zkApp command, and the first proof found in account updates.
pub fn parse_graphql_zkapp(graphql_str: &str) -> Result<ParsedZkappTransaction> {
    let schema = RootNode::new(Query, Mutation, EmptySubscription::<Context>::new());
    let ctx = Context {
        result: Mutex::new(None),
    };

    let (_value, errors) = execute_sync(graphql_str, None, &schema, &Variables::new(), &ctx)
        .map_err(|e| anyhow::anyhow!("GraphQL execution error: {e:?}"))?;

    if !errors.is_empty() {
        return Err(anyhow::anyhow!("GraphQL field errors: {errors:?}"));
    }

    let wire_command =
        ctx.result.lock().unwrap().take().ok_or_else(|| {
            anyhow::anyhow!("No transaction was parsed from the GraphQL mutation")
        })?;

    let zkapp_command = match &wire_command {
        MinaBaseUserCommandStableV2::ZkappCommand(cmd) => cmd.clone(),
        _ => return Err(anyhow::anyhow!("Expected ZkappCommand variant")),
    };

    let proof = extract_first_proof(&zkapp_command)?;

    Ok(ParsedZkappTransaction {
        wire_command,
        zkapp_command,
        proof,
    })
}

/// Read a GraphQL mutation file from disk and parse it.
pub fn parse_graphql_zkapp_file(path: &str) -> Result<ParsedZkappTransaction> {
    let graphql_str =
        std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("Read {path}: {e}"))?;
    parse_graphql_zkapp(&graphql_str)
}

/// Decode a standalone base64-encoded S-expression proof.
pub fn proof_from_b64_sexp(
    proof_sexp_b64: &str,
) -> Result<PicklesProofProofsVerified2ReprStableV2> {
    let sexp_bytes = general_purpose::STANDARD
        .decode(proof_sexp_b64.trim())
        .map_err(|e| anyhow::anyhow!("base64 decode proof: {e:?}"))?;

    let sexp =
        rsexp::from_slice(&sexp_bytes).map_err(|e| anyhow::anyhow!("parse proof S-exp: {e:?}"))?;

    PicklesProofProofsVerified2ReprStableV2::of_sexp(&sexp)
        .map_err(|e| anyhow::anyhow!("S-exp -> proof decode: {e:?}"))
}

// ---------------------------------------------------------------------------
// o1js JSON proof format
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct O1jsProofJson {
    pub public_input: Vec<String>,
    pub public_output: Vec<String>,
    pub max_proofs_verified: u8,
    pub proof: String, // base64-encoded S-expression
}

/// Parsed o1js proof with all components extracted.
pub struct ParsedO1jsProof {
    pub public_input: Vec<String>,
    pub public_output: Vec<String>,
    pub max_proofs_verified: u8,
    pub proof: PicklesProofProofsVerified2ReprStableV2,
}

pub fn parse_o1js_proof_json(json_str: &str) -> Result<ParsedO1jsProof> {
    let json: O1jsProofJson =
        serde_json::from_str(json_str).map_err(|e| anyhow::anyhow!("JSON parse: {e}"))?;

    let sexp_bytes = general_purpose::STANDARD
        .decode(json.proof.trim())
        .map_err(|e| anyhow::anyhow!("base64 decode proof: {e:?}"))?;

    let sexp =
        rsexp::from_slice(&sexp_bytes).map_err(|e| anyhow::anyhow!("parse proof S-exp: {e:?}"))?;

    let sexp = pad_proof_sexp_to_n2(sexp, json.max_proofs_verified)?;

    let proof = PicklesProofProofsVerified2ReprStableV2::of_sexp(&sexp)
        .map_err(|e| anyhow::anyhow!("S-exp -> proof decode: {e:?}"))?;

    Ok(ParsedO1jsProof {
        public_input: json.public_input,
        public_output: json.public_output,
        max_proofs_verified: json.max_proofs_verified,
        proof,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Walk account updates and return the first proof found.
fn extract_first_proof(
    zkapp: &MinaBaseZkappCommandTStableV1WireStableV1,
) -> Result<PicklesProofProofsVerified2ReprStableV2> {
    for update in zkapp.account_updates.iter() {
        if let MinaBaseControlStableV2::Proof(proof) = &update.elt.account_update.authorization {
            return Ok((*proof.clone()).into());
        }
    }
    Err(anyhow::anyhow!(
        "No proof found in any account update authorization"
    ))
}

/// Pad an N0/N1 proof sexp so it deserializes as N2.
fn pad_proof_sexp_to_n2(sexp: Sexp, max_proofs_verified: u8) -> Result<Sexp> {
    if max_proofs_verified >= 2 {
        return Ok(sexp);
    }
    let mut sexp = sexp;
    if !pad_wrap_challenges(&mut sexp, max_proofs_verified as usize) {
        return Err(anyhow::anyhow!(
            "Could not find old_bulletproof_challenges to pad"
        ));
    }
    Ok(sexp)
}

/// Recursively find and pad `old_bulletproof_challenges` to 2 entries.
fn pad_wrap_challenges(sexp: &mut Sexp, current_len: usize) -> bool {
    if let Sexp::List(items) = sexp {
        if items.len() == current_len
            && current_len > 0
            && items
                .iter()
                .all(|i| matches!(i, Sexp::List(v) if v.len() == 15))
        {
            let padding = items[0].clone();
            while items.len() < 2 {
                items.insert(0, padding.clone());
            }
            return true;
        }
        for item in items.iter_mut() {
            if pad_wrap_challenges(item, current_len) {
                return true;
            }
        }
    }
    false
}

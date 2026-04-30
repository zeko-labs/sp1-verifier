// ---------------------------------------------------------------------------
// parser.rs — host-only parsing helpers
// Ported verbatim from verification-test/src/lib.rs.
// None of this code runs inside the SP1 guest (zkVM).
// ---------------------------------------------------------------------------

use anyhow::Result;
use juniper::{execute_sync, graphql_object, EmptySubscription, FieldResult, RootNode, Variables};
use mina_node_native::graphql::zkapp::{GraphQLSendZkappResponse, SendZkappInput};
use mina_p2p_messages::v2::{
    MinaBaseControlStableV2, MinaBaseUserCommandStableV2,
    MinaBaseZkappCommandTStableV1WireStableV1, PicklesProofProofsVerified2ReprStableV2,
};
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

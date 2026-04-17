use mina_p2p_messages::v2::{
    MinaBaseUserCommandStableV2, MinaBaseZkappCommandTStableV1WireStableV1,
    PicklesProofProofsVerified2ReprStableV2,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Shared types — used by both host (script) and guest (program)
// All field elements (Fp) are serialized as [u8; 32] to avoid
// pulling mina-curves into the lib crate.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ParsedZkappTransaction {
    pub wire_command: MinaBaseUserCommandStableV2,
    pub zkapp_command: MinaBaseZkappCommandTStableV1WireStableV1,
    pub proof: PicklesProofProofsVerified2ReprStableV2,
}

/// Account precondition coming from the Solidity smart contract.
/// Each field is Option: None means "no constraint" (wildcard).
/// This will be committed as a public value so Solidity can verify
/// that the guest used the expected preconditions.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccountPrecondition {
    /// Balance in nanomina
    pub balance: Option<u64>,
    /// Account nonce
    pub nonce: Option<u32>,
    /// Receipt chain hash as raw bytes
    pub receipt_chain_hash: Option<[u8; 32]>,
    /// Delegate public key (compressed)
    pub delegate: Option<[u8; 32]>,
    /// zkApp state array — 8 field elements as bytes, None = wildcard
    pub state: [Option<[u8; 32]>; 8],
    /// Action state as bytes
    pub action_state: Option<[u8; 32]>,
    /// Whether the account has been proved
    pub proved_state: Option<bool>,
    /// Whether the account is new
    pub is_new: Option<bool>,
}

impl Default for AccountPrecondition {
    fn default() -> Self {
        Self {
            balance: None,
            nonce: None,
            receipt_chain_hash: None,
            delegate: None,
            state: [None; 8],
            action_state: None,
            proved_state: None,
            is_new: None,
        }
    }
}

/// Public values committed by the guest — verifiable in Solidity via
/// `ISP1Verifier.verifyProof(programVKey, abi.encode(public_values), proof)`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ZkappPublicValues {
    pub proof_valid: bool,
}

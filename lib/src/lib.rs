use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Shared types — used by both host (script) and guest (program)
// All field elements (Fp) are serialized as [u8; 32] to avoid
// pulling mina-curves into the lib crate.
// ---------------------------------------------------------------------------

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
    /// Preconditions the guest enforced (echoed back for on-chain verification)
    pub precondition: AccountPrecondition,
    /// Merkle root of the ledger before applying the transaction
    pub state_root_before: [u8; 32],
    /// Merkle root of the ledger after applying the transaction
    pub state_root_after: [u8; 32],
    /// Hash of the zkApp transaction
    pub tx_hash: [u8; 32],
    /// true = Applied, false = Failed
    pub transaction_applied: bool,
}

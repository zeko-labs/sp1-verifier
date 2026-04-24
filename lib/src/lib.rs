use mina_curves::pasta::{Fp, Fq, Pallas};
use mina_p2p_messages::v2::{
    MinaBaseUserCommandStableV2, MinaBaseZkappCommandTStableV1WireStableV1,
    PicklesProofProofsVerified2ReprStableV2,
};
use mina_poseidon::pasta::fp_kimchi;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::FULL_ROUNDS,
    poseidon::{ArithmeticSponge as Poseidon, Sponge},
};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// rkyv structs — used only for static SRS file embedding (include_bytes!)
// ---------------------------------------------------------------------------

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Clone, Debug)]
#[rkyv(derive(Debug))]
pub struct RkyvPoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub infinity: bool,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Clone, Debug)]
#[rkyv(derive(Debug))]
pub struct RkyvPolyComm {
    pub chunks: Vec<RkyvPoint>,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Clone, Debug)]
#[rkyv(derive(Debug))]
pub struct RkyvSRS {
    pub g: Vec<RkyvPoint>,
    pub h: RkyvPoint,
    pub domain_size: usize,
    pub lagrange_bases: Vec<RkyvPolyComm>,
}

// ---------------------------------------------------------------------------
// Host-only — parsing helpers
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ParsedZkappTransaction {
    pub wire_command: MinaBaseUserCommandStableV2,
    pub zkapp_command: MinaBaseZkappCommandTStableV1WireStableV1,
    pub proof: PicklesProofProofsVerified2ReprStableV2,
}

// ---------------------------------------------------------------------------
// serde — used by sp1_zkvm::io::commit and bincode for host/guest I/O
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ZkappPublicValues {
    pub proof_valid: bool,
}

pub fn poseidon_hash(input: &[Fp]) -> Fp {
    let mut hash =
        Poseidon::<Fp, PlonkSpongeConstantsKimchi, FULL_ROUNDS>::new(fp_kimchi::static_params());
    hash.absorb(input);
    hash.squeeze()
}

//! Zeko SP1 — zkApp proof verifier
//!
//! Execute (no proof):
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! Prove (core proof):
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

#![no_main]
sp1_zkvm::entrypoint!(main);

use ledger::{proofs::verification::verify_zkapp, verifier::get_srs, VerificationKey};
use mina_curves::pasta::{Fp, Vesta};
use mina_p2p_messages::v2::{
    MinaBaseVerificationKeyWireStableV1, PicklesProofProofsVerified2ReprStableV2,
};
use zeko_sp1_lib::ZkappPublicValues;

// ZkappStatement type — adjust the import path to wherever it lives in your ledger crate
use ledger::proofs::verification::ZkappStatement;

pub fn main() {
    // ------------------------------------------------------------------
    // 1. Read inputs from stdin
    //    Order MUST match stdin.write() calls in script/src/main.rs
    //    1. zkapp_stmt  (prepared on host via check())
    //    2. proof
    //    3. vk_wire
    // ------------------------------------------------------------------
    let zkapp_stmt: ZkappStatement = sp1_zkvm::io::read();
    let proof: PicklesProofProofsVerified2ReprStableV2 = sp1_zkvm::io::read();
    let vk_wire: MinaBaseVerificationKeyWireStableV1 = sp1_zkvm::io::read();

    // ------------------------------------------------------------------
    // 2. Convert wire VK to runtime
    // ------------------------------------------------------------------
    let verification_key: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime");

    // ------------------------------------------------------------------
    // 3. verify_zkapp — single call, replaces steps 3-6 of the old guest
    //    accumulator_check + verify_impl are both done inside
    // ------------------------------------------------------------------
    let srs = get_srs::<Vesta>();
    let proof_valid = verify_zkapp(&verification_key, &zkapp_stmt, &proof, &srs);

    assert!(proof_valid, "Pickles proof invalid");

    // ------------------------------------------------------------------
    // 4. Commit public values
    // ------------------------------------------------------------------
    let vk_hash = vk_hash_bytes(&verification_key);

    sp1_zkvm::io::commit(&ZkappPublicValues {
        vk_hash,
        proof_valid,
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hash the VK to a [u8; 32] for the public output.
fn vk_hash_bytes(vk: &VerificationKey) -> [u8; 32] {
    use ark_serialize::CanonicalSerialize;
    use sha2::{Digest, Sha256};
    let mut buf = Vec::new();
    vk.wrap_index
        .serialize_uncompressed(&mut buf)
        .expect("serialize vk");
    Sha256::digest(&buf).into()
}

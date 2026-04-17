#![no_main]
sp1_zkvm::entrypoint!(main);

use ledger::scan_state::transaction_logic::zkapp_statement::ZkappStatement;
use ledger::{proofs::verification::verify_zkapp, verifier::get_srs, VerificationKey};
use mina_curves::pasta::{Fp, Vesta};
use mina_p2p_messages::v2::{
    MinaBaseVerificationKeyWireStableV1, PicklesProofProofsVerified2ReprStableV2,
};
use zeko_sp1_lib::ZkappPublicValues;

pub fn main() {
    let zkapp_stmt: ZkappStatement = sp1_zkvm::io::read();
    let proof: PicklesProofProofsVerified2ReprStableV2 = sp1_zkvm::io::read();
    let vk_wire: MinaBaseVerificationKeyWireStableV1 = sp1_zkvm::io::read();

    let verification_key: VerificationKey = (&vk_wire).try_into().expect("vk wire -> runtime");

    let srs = get_srs::<Fp>();
    let proof_valid = verify_zkapp(&verification_key, &zkapp_stmt, &proof, &srs);

    assert!(proof_valid, "Pickles proof invalid");

    sp1_zkvm::io::commit(&ZkappPublicValues { proof_valid });
}

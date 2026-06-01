#![cfg_attr(not(test), no_main)]
#[cfg(not(test))]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::keccak256;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use mina_curves::pasta::Fp;
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use mina_poseidon::pasta::{fp_kimchi, FULL_ROUNDS};
use mina_poseidon::permutation::poseidon_block_cipher;
use zeko_sp1_lib::{Address, Bytes32, WithdrawTransitionInput, WithdrawTransitionPublicValues};

fn main() {
    let input: WithdrawTransitionInput = sp1_zkvm::io::read();

    let mut ethereum_withdraw_state = input.ethereum.withdraw_state;
    let mut zeko_action_state = fp_from_bytes(input.zeko.action_state);

    let empty_action_list_hash = empty_hash_with_prefix("MinaZkappActionsEmpty");

    for withdraw in &input.withdraws {
        let ethereum_withdraw_leaf = compute_ethereum_withdraw_leaf(
            input.ethereum.chain_id,
            input.ethereum.bridge_address,
            withdraw.token,
            withdraw.recipient,
            withdraw.amount,
        );

        ethereum_withdraw_state =
            compute_ethereum_withdraw_state(ethereum_withdraw_state, ethereum_withdraw_leaf);

        let zeko_action_hash =
            compute_zeko_withdraw_action_hash(withdraw.recipient, withdraw.amount);
        let zeko_action_list_hash = action_list_add(empty_action_list_hash, zeko_action_hash);
        zeko_action_state = merkle_actions_add(zeko_action_state, zeko_action_list_hash);
    }

    sp1_zkvm::io::commit(&WithdrawTransitionPublicValues {
        zeko_action_state_before: fp_to_bytes(fp_from_bytes(input.zeko.action_state)),
        zeko_action_state_after: fp_to_bytes(zeko_action_state),
        ethereum_withdraw_state_before: input.ethereum.withdraw_state,
        ethereum_withdraw_state_after: ethereum_withdraw_state,
        withdraw_count: input.withdraws.len() as u32,
    });
}

fn compute_ethereum_withdraw_leaf(
    chain_id: u64,
    bridge_address: Address,
    token: Bytes32,
    recipient: Bytes32,
    amount: Bytes32,
) -> Bytes32 {
    let mut encoded = Vec::with_capacity(32 * 6);
    encoded.extend_from_slice(&keccak256("ZEKO_BRIDGE_WITHDRAW_LEAF_V1".as_bytes()).0);
    encoded.extend_from_slice(&u64_word(chain_id));
    encoded.extend_from_slice(&address_word(bridge_address));
    encoded.extend_from_slice(&token);
    encoded.extend_from_slice(&recipient);
    encoded.extend_from_slice(&amount);
    keccak256(encoded).0
}

fn compute_ethereum_withdraw_state(previous_state: Bytes32, withdraw_leaf: Bytes32) -> Bytes32 {
    let mut encoded = Vec::with_capacity(96);
    encoded.extend_from_slice(&keccak256("ZEKO_BRIDGE_WITHDRAW_STATE_V1".as_bytes()).0);
    encoded.extend_from_slice(&previous_state);
    encoded.extend_from_slice(&withdraw_leaf);
    keccak256(encoded).0
}

fn compute_zeko_withdraw_action_hash(recipient: Bytes32, amount: Bytes32) -> Fp {
    let fields = [
        Fp::from(0u8),
        fp_from_bytes(amount),
        fp_from_bytes(recipient),
    ];

    hash_with_prefix("Withdrawal_params - qFB3jXP*)", &fields)
}

fn action_list_add(hash: Fp, action: Fp) -> Fp {
    let event_hash = hash_with_prefix("MinaZkappEvent******", &[action]);
    hash_with_prefix("MinaZkappSeqEvents**", &[hash, event_hash])
}

fn merkle_actions_add(hash: Fp, actions_hash: Fp) -> Fp {
    hash_with_prefix("MinaZkappSeqEvents**", &[hash, actions_hash])
}

fn empty_hash_with_prefix(prefix: &str) -> Fp {
    poseidon_update(
        [Fp::from(0u8), Fp::from(0u8), Fp::from(0u8)],
        &[prefix_to_field(prefix)],
    )[0]
}

fn hash_with_prefix(prefix: &str, input: &[Fp]) -> Fp {
    let init = poseidon_update(
        [Fp::from(0u8), Fp::from(0u8), Fp::from(0u8)],
        &[prefix_to_field(prefix)],
    );
    poseidon_update(init, input)[0]
}

fn poseidon_update(mut state: [Fp; 3], input: &[Fp]) -> [Fp; 3] {
    if input.is_empty() {
        poseidon_block_cipher::<Fp, PlonkSpongeConstantsKimchi, FULL_ROUNDS>(
            fp_kimchi::static_params(),
            &mut state,
        );
        return state;
    }

    for chunk in input.chunks(2) {
        state[0] += chunk[0];
        if chunk.len() == 2 {
            state[1] += chunk[1];
        }
        poseidon_block_cipher::<Fp, PlonkSpongeConstantsKimchi, FULL_ROUNDS>(
            fp_kimchi::static_params(),
            &mut state,
        );
    }

    state
}

fn prefix_to_field(prefix: &str) -> Fp {
    assert!(prefix.len() < 32, "prefix too long");
    let mut bytes = [0u8; 32];
    bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
    Fp::from_le_bytes_mod_order(&bytes)
}

fn fp_from_bytes(bytes: Bytes32) -> Fp {
    Fp::from_be_bytes_mod_order(&bytes)
}

fn fp_to_bytes(x: Fp) -> Bytes32 {
    let mut buf = [0u8; 32];
    x.serialize_uncompressed(&mut buf[..])
        .expect("serialize field");
    buf.reverse();
    buf
}

fn u64_word(value: u64) -> Bytes32 {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&value.to_be_bytes());
    word
}

fn address_word(address: Address) -> Bytes32 {
    let mut word = [0u8; 32];
    word[12..32].copy_from_slice(&address);
    word
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn withdrawal_hash_matches_zeko_aux_shape() {
        let recipient = hex32("0000000000000000000000000000000000000000000000000000000001020304");
        let amount = hex32("000000000000000000000000000000000000000000000000000000003b9aca00");

        let action_hash = compute_zeko_withdraw_action_hash(recipient, amount);
        let expected = hash_with_prefix(
            "Withdrawal_params - qFB3jXP*)",
            &[
                Fp::from(0u8),
                fp_from_bytes(amount),
                fp_from_bytes(recipient),
            ],
        );

        assert_eq!(action_hash, expected);
    }

    fn hex32(value: &str) -> [u8; 32] {
        let value = value.strip_prefix("0x").unwrap_or(value);
        assert_eq!(value.len(), 64);

        let bytes = value.as_bytes();
        let mut output = [0u8; 32];
        for i in 0..32 {
            output[i] = (hex_nibble(bytes[i * 2]) << 4) | hex_nibble(bytes[i * 2 + 1]);
        }
        output
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex byte"),
        }
    }
}

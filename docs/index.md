# Zeko SP1 Verifier Documentation

This project uses SP1 to produce Ethereum-verifiable proofs for Zeko settlement and bridge transitions.

The system is split into two circuits:

- **Settlement** proves that a Zeko/o1 zkApp proof is valid and extracts the rollup state transition Ethereum should accept.
- **Bridge** proves that Ethereum deposits produce the expected Zeko action-state transition.

## System Overview

```text
Ethereum contracts / fixtures
        |
        v
Host scripts encode inputs
        |
        v
SP1 guest programs
        |
        v
SP1 public values
        |
        v
Ethereum verifier contracts
```

## Settlement

The settlement circuit lives in `program/settlement`.

It verifies a Zeko/o1 proof inside SP1. The guest receives:

- the Zeko verification key
- the o1 proof
- the zkApp statement
- deferred proof values
- the zkApp command
- the verifier index

The guest then:

1. Deserializes all proof and command data.
2. Checks that the first account update in the zkApp command matches the zkApp statement.
3. Reconstructs the verifier index with the embedded SRS from `srs_rkyv.bin`.
4. Reconstructs skipped verifier fields such as linearization data and endomorphism constants.
5. Runs Kimchi verification.
6. Extracts the canonical settlement values from the first account update.
7. Commits these values as SP1 public output.

### Settlement Public Values

`ZkappPublicValues` contains:

| Field | Meaning |
| --- | --- |
| `proof_valid` | Whether Kimchi verification succeeded. |
| `vk_hash` | Hash of the Zeko verification key used by the proof. |
| `state_before` | Eight zkApp state slots before the transition. |
| `state_after` | Eight zkApp state slots after the transition. |
| `action_state_before` | Action state required by the zkApp account precondition. |

### Ethereum Settlement Contract

`contracts/src/ZekoProofVerifier.sol` verifies the SP1 proof and enforces Ethereum-side state continuity.

It checks:

- the SP1 proof verifies under `programVKey`
- `proof_valid == true`
- the proof's `vk_hash` equals the stored `vkHash`
- the proof's `action_state_before` equals the stored `actionState`
- `state_before[3]` equals the stored `currentRoot`

If all checks pass, it updates `currentRoot` to `state_after[3]`.

## Bridge

The bridge circuit lives in `program/bridge`.

It proves that a batch of deposits recorded on Ethereum maps to a valid Zeko action-state transition.

### Bridge Inputs

`BridgeTransitionInput` contains:

| Field | Meaning |
| --- | --- |
| `ethereum.chain_id` | Ethereum chain id used in deposit leaf domain separation. |
| `ethereum.bridge_address` | L1 bridge address, also used as `holderAccountL1` for the Zeko action. |
| `ethereum.deposit_nonce` | Last processed Ethereum deposit nonce. |
| `ethereum.deposit_state` | Current Ethereum deposit accumulator state. |
| `zeko.action_state` | Current Zeko action state. |
| `deposits[]` | Batch of deposits to apply. |

Each deposit contains:

| Field | Meaning |
| --- | --- |
| `token` | L1 token address, or zero address for native ETH in contract semantics. |
| `amount` | Original Ethereum-side amount. |
| `zeko_amount` | Amount normalized to Zeko decimals. |
| `zeko_recipient` | Packed Zeko address. |
| `timeout` | Deposit timeout used by the Zeko action. |

Human-readable JSON accepts hex strings and decimal strings for fixed-width values.

### Deposit Leaf

The bridge computes the same deposit leaf as `EthereumZekoBridge.sol`:

```text
keccak256(
  ZEKO_BRIDGE_DEPOSIT_LEAF_V1,
  chain_id,
  bridge_address,
  token,
  zeko_recipient,
  zeko_amount,
  timeout,
  nonce
)
```

The Ethereum deposit accumulator is:

```text
keccak256(
  ZEKO_BRIDGE_DEPOSIT_STATE_V1,
  previous_deposit_state,
  deposit_leaf
)
```

### Zeko Action

The bridge action payload matches the Zeko deposit format:

```text
Poseidon.hashWithPrefix("Deposit_params - qFB3jXP*)", [
  Field(0),
  holderAccountL1,
  zekoAmount,
  recipient.x,
  recipient.isOdd,
  timeout
])
```

The packed `ZekoAddress` stores:

- lower 255 bits: recipient `x`
- top bit: `isOdd`

The circuit validates that `x` is below the Pasta Fp field order before using it.

### Zeko Action State

For every deposit, the bridge creates one action list and appends it to the Zeko action-state sequence.

The Poseidon helper intentionally mirrors o1js `Poseidon.hashWithPrefix()` semantics:

1. `Poseidon.update(initial_state, [prefix])`
2. `Poseidon.update(prefixed_state, input)`
3. padding by rate-2 blocks

This matters because a generic sponge absorb of `prefix + input` does not produce the same value.

### Bridge Public Values

`BridgeTransitionPublicValues` contains:

| Field | Meaning |
| --- | --- |
| `ethereum_state_before` | Ethereum deposit accumulator before the batch. |
| `ethereum_state_after` | Ethereum deposit accumulator after the batch. |
| `ethereum_nonce_before` | Starting nonce. |
| `ethereum_nonce_after` | Final nonce. |
| `zeko_action_state_before` | Zeko action state before the batch. |
| `zeko_action_state_after` | Zeko action state after the batch. |
| `deposit_count` | Number of deposits applied. |
| `resolved_deposits` | Per-deposit leaf, action hash, action-list hash, and action-state checkpoint. |

## Ethereum Bridge Contract

`contracts/src/EthereumZekoBridge.sol` is the Ethereum-side deposit contract.

It:

- stores allowed token configurations
- normalizes Ethereum token amounts into Zeko decimals
- rejects fee-on-transfer ERC20 deposits
- stores an append-only deposit accumulator by nonce
- emits every deposit leaf and accumulator checkpoint

Withdrawals are not implemented in the current contract.

## Useful Commands

Run the bridge circuit without proving:

```sh
cargo run --release --bin bridge -- --execute
```

Generate a bridge core proof:

```sh
cargo run --release --bin bridge -- --prove
```

Run the Zeko action-state o1js fixture:

```sh
cd tools/zeko-action-state
npm install
npm start
```

Run the bridge action-state regression test:

```sh
cargo test -p bridge-program fixture_deposit_matches_zeko_action_state
```

Run the host-side bridge check:

```sh
cargo check -p zeko_sp1_lib -p bridge-program -p zkapp-script --bin bridge
```

## Current Fixture

The current `proofs/bridge-input.json` fixture has three deposits and starts from the Zeko empty action state:

```text
0x3772bc5435b957f81f86f752e93f2e29e886ac24580b3d1ec879c1dad26965f9
```

Expected final Zeko action state:

```text
0x3d638b908c4241e7b417d1790a79d0fe3277a133a5a87e12a484cd756de795bf
```

## Trust Boundaries

The settlement proof verifies Zeko/o1 validity and extracts state transition data. The Ethereum contract then checks continuity against its own tracked state.

The bridge proof does not prove that Ethereum events happened by itself; it proves that a supplied batch of deposits transforms the Ethereum deposit accumulator and Zeko action state correctly. The Ethereum contract accumulator and the verifier integration are what bind those public values to on-chain deposit history.

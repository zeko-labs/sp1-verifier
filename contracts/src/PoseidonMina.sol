// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @title PoseidonMina
/// @notice This contract verifies SP1 proofs for Poseidon hash computation (Mina-style).
/// @dev The circuit takes two u64 inputs (a, b) and outputs a single bytes32 hash.
contract PoseidonMina {
    /// @notice The address of the SP1 verifier contract.
    address public verifier;

    /// @notice The verification key for the PoseidonMina program.
    bytes32 public poseidonMinaProgramVKey;

    constructor(address _verifier, bytes32 _poseidonMinaProgramVKey) {
        verifier = _verifier;
        poseidonMinaProgramVKey = _poseidonMinaProgramVKey;
    }

    /// @notice Verifies a Poseidon hash proof and returns the hash result.
    /// @param _publicValues The encoded public values (32 bytes = the hash result).
    /// @param _proofBytes The encoded proof.
    /// @return result The Poseidon hash result as bytes32.
    function verifyPoseidonProof(bytes calldata _publicValues, bytes calldata _proofBytes)
        public
        view
        returns (bytes32 result)
    {
        // Check length BEFORE calling verifier (fail fast, save gas)
        require(_publicValues.length == 32, "Invalid public values length");
        
        ISP1Verifier(verifier).verifyProof(poseidonMinaProgramVKey, _publicValues, _proofBytes);
        
        result = bytes32(_publicValues);
    }

    /// @notice Verifies that a given hash matches the proven computation.
    /// @param _publicValues The encoded public values (32 bytes = the hash result).
    /// @param _proofBytes The encoded proof.
    /// @param _expectedHash The expected hash to verify against.
    /// @return valid True if the proof is valid and hash matches.
    function verifyPoseidonHash(
        bytes calldata _publicValues,
        bytes calldata _proofBytes,
        bytes32 _expectedHash
    ) public view returns (bool valid) {
        bytes32 result = verifyPoseidonProof(_publicValues, _proofBytes);
        return result == _expectedHash;
    }
}
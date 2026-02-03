module poseidon_mina::verifier {
    use sui::groth16;
    use sui::event;

    // ============ Errors ============
    const EProofVerificationFailed: u64 = 0;
    const EInvalidPublicInputsLength: u64 = 1;

    // ============ Events ============
    
    /// Event emitted after successful verification
    public struct VerificationSuccess has copy, drop {
        public_inputs_hash: vector<u8>,
    }

    /// Event emitted after failed verification
    public struct VerificationFailed has copy, drop {
        reason: vector<u8>,
    }

    // ============ Public Functions ============

    /// Verify a SP1 Groth16 proof for Poseidon hash computation
    /// Returns true if the proof is valid, false otherwise
    public fun verify_poseidon_proof(
        pvk_bytes: vector<u8>,           // Prepared verification key (ark-bn254 format)
        public_inputs_bytes: vector<u8>, // Public inputs (the hash result)
        proof_points_bytes: vector<u8>,  // The proof points (ark-bn254 format)
    ): bool {
        // Use BN254 curve (same as Ethereum)
        let curve = groth16::bn254();
        
        // Prepare the verification key
        let pvk = groth16::prepare_verifying_key(&curve, &pvk_bytes);
        
        // Parse public inputs
        let public_inputs = groth16::public_proof_inputs_from_bytes(public_inputs_bytes);
        
        // Parse proof points
        let proof_points = groth16::proof_points_from_bytes(proof_points_bytes);
        
        // Verify the Groth16 proof
        groth16::verify_groth16_proof(&curve, &pvk, &public_inputs, &proof_points)
    }

    /// Entry function to verify a proof and emit events
    public entry fun verify_and_emit(
        pvk_bytes: vector<u8>,
        public_inputs_bytes: vector<u8>,
        proof_points_bytes: vector<u8>,
    ) {
        let is_valid = verify_poseidon_proof(
            pvk_bytes,
            public_inputs_bytes,
            proof_points_bytes
        );

        if (is_valid) {
            event::emit(VerificationSuccess {
                public_inputs_hash: public_inputs_bytes,
            });
        } else {
            event::emit(VerificationFailed {
                reason: b"Proof verification failed",
            });
        };
    }

    /// Entry function that asserts the proof is valid (reverts if invalid)
    public entry fun verify_or_abort(
        pvk_bytes: vector<u8>,
        public_inputs_bytes: vector<u8>,
        proof_points_bytes: vector<u8>,
    ) {
        let is_valid = verify_poseidon_proof(
            pvk_bytes,
            public_inputs_bytes,
            proof_points_bytes
        );
        
        assert!(is_valid, EProofVerificationFailed);
        
        event::emit(VerificationSuccess {
            public_inputs_hash: public_inputs_bytes,
        });
    }
}
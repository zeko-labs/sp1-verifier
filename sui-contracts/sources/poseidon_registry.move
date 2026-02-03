module poseidon_mina::registry {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::table::{Self, Table};
    use sui::event;
    use poseidon_mina::verifier;

    // ============ Errors ============
    const EAlreadyVerified: u64 = 0;
    const EProofInvalid: u64 = 1;

    // ============ Objects ============

    /// Registry to store verified proofs
    public struct VerificationRegistry has key {
        id: UID,
        // Maps public_inputs_hash -> verified (bool)
        verified_proofs: Table<vector<u8>, bool>,
        total_verifications: u64,
    }

    // ============ Events ============

    public struct ProofRegistered has copy, drop {
        public_inputs: vector<u8>,
        verifier: address,
    }

    // ============ Init ============

    fun init(ctx: &mut TxContext) {
        let registry = VerificationRegistry {
            id: object::new(ctx),
            verified_proofs: table::new(ctx),
            total_verifications: 0,
        };
        transfer::share_object(registry);
    }

    // ============ Public Functions ============

    /// Verify a proof and register it in the registry
    public entry fun verify_and_register(
        registry: &mut VerificationRegistry,
        pvk_bytes: vector<u8>,
        public_inputs_bytes: vector<u8>,
        proof_points_bytes: vector<u8>,
        ctx: &mut TxContext,
    ) {
        // Check if already verified
        assert!(
            !table::contains(&registry.verified_proofs, public_inputs_bytes),
            EAlreadyVerified
        );

        // Verify the proof
        let is_valid = verifier::verify_poseidon_proof(
            pvk_bytes,
            public_inputs_bytes,
            proof_points_bytes
        );
        
        assert!(is_valid, EProofInvalid);

        // Register the proof
        table::add(&mut registry.verified_proofs, public_inputs_bytes, true);
        registry.total_verifications = registry.total_verifications + 1;

        event::emit(ProofRegistered {
            public_inputs: public_inputs_bytes,
            verifier: tx_context::sender(ctx),
        });
    }

    /// Check if a proof has been verified
    public fun is_verified(
        registry: &VerificationRegistry,
        public_inputs_bytes: vector<u8>,
    ): bool {
        table::contains(&registry.verified_proofs, public_inputs_bytes)
    }

    /// Get total number of verifications
    public fun total_verifications(registry: &VerificationRegistry): u64 {
        registry.total_verifications
    }
}
use alloy_sol_types::sol;
use openzeppelin_crypto::{
    arithmetic::uint::U256,
    field::{instance::FpKimchi, prime::PrimeField},
    poseidon_mina::{instance::kimchi::KimchiParams, PoseidonMina},
};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 n;
        uint32 a;
        uint32 b;
    }
}

pub fn hash(vec: Vec<alloy_primitives::U256>) -> alloy_primitives::U256 {
    let mut poseidon = PoseidonMina::<KimchiParams, FpKimchi>::new();

    for input in vec.iter() {
        let fp = FpKimchi::from_bigint(U256::from(*input));
        poseidon.absorb(&[fp]);
    }

    let hash = poseidon.squeeze();
    hash.into_bigint().into()
}

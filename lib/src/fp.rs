// src/fp.rs
use crypto_bigint::{Encoding, NonZero, U256, U512};

const MODULUS_U256: U256 =
    U256::from_be_hex("40000000000000000000000000000000224698fc094cf91b992d30ed00000001");

const MODULUS: NonZero<U256> = NonZero::from_uint(MODULUS_U256);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp(U256);

impl Fp {
    pub const ZERO: Self = Fp(U256::ZERO);
    pub const ONE: Self = Fp(U256::ONE);

    pub const fn from_be_hex(s: &str) -> Self {
        Fp(U256::from_be_hex(s))
    }

    pub fn from(v: u64) -> Self {
        Fp(U256::from(v))
    }

    #[inline(always)]
    pub fn add(self, rhs: Self) -> Self {
        Fp(self.0.add_mod(&rhs.0, &MODULUS_U256))
    }

    #[inline(always)]
    pub fn sub(self, rhs: Self) -> Self {
        Fp(self.0.sub_mod(&rhs.0, &MODULUS_U256))
    }

    #[inline(always)]
    pub fn mul(self, rhs: Self) -> Self {
        #[cfg(target_os = "zkvm")]
        {
            extern "C" {
                fn syscall_uint256_mulmod(x: *mut u32, y: *const u32);
            }
            let mut result = self.0.to_le_bytes();
            let rhs_bytes = rhs.0.to_le_bytes();
            unsafe {
                syscall_uint256_mulmod(
                    result.as_mut_ptr() as *mut u32,
                    rhs_bytes.as_ptr() as *const u32,
                );
            }
            Fp(U256::from_le_bytes(result))
        }
        #[cfg(not(target_os = "zkvm"))]
        {
            let (lo, hi) = self.0.mul_wide(&rhs.0);
            let wide = U512::from((lo, hi));
            let modulus_512 = U512::from((MODULUS_U256, U256::ZERO));
            let (_, rem) = wide.div_rem(&NonZero::from_uint(modulus_512));
            Fp(U256::from_le_bytes(
                rem.to_le_bytes()[..32].try_into().unwrap(),
            ))
        }
    }

    #[inline(always)]
    pub fn pow7(self) -> Self {
        let x2 = self.mul(self);
        let x4 = x2.mul(x2);
        let x6 = x4.mul(x2);
        x6.mul(self)
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        Encoding::to_be_bytes(&self.0)
    }

    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Fp(<U256 as Encoding>::from_be_bytes(bytes))
    }
}

use core::fmt;
use crypto_bigint::{Encoding, NonZero, U256, U512};

const MODULUS_U256: U256 =
    U256::from_be_hex("40000000000000000000000000000000224698fc094cf91b992d30ed00000001");

const MODULUS: NonZero<U256> = NonZero::from_uint(MODULUS_U256);

// Pallas modulus as u64 limbs, little-endian
const PALLAS_MODULUS_LIMBS: [u64; 4] = [
    0x992d30ed00000001,
    0x224698fc094cf91b,
    0x0000000000000000,
    0x4000000000000000,
];

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
        let out = Fp(self.0.add_mod(&rhs.0, &MODULUS_U256));
        out
    }

    #[inline(always)]
    pub fn sub(self, rhs: Self) -> Self {
        let out = Fp(self.0.sub_mod(&rhs.0, &MODULUS_U256));
        out
    }

    #[inline(always)]
    pub fn mul(self, rhs: Self) -> Self {
        let lhs_limbs: [u64; 4] = bytemuck::cast(self.0.to_le_bytes());
        let rhs_limbs: [u64; 4] = bytemuck::cast(rhs.0.to_le_bytes());
        let mut result: [u64; 4] = [0u64; 4];

        #[cfg(target_os = "zkvm")]
        unsafe {
            sp1_lib::sys_bigint(
                &mut result as *mut [u64; 4],
                0, // OP_MULMOD
                &lhs_limbs as *const [u64; 4],
                &rhs_limbs as *const [u64; 4],
                &PALLAS_MODULUS_LIMBS as *const [u64; 4],
            );
        }
        let out = Fp(U256::from_le_bytes(bytemuck::cast(result)));

        out
    }

    #[inline(always)]
    pub fn pow7(self) -> Self {
        std::println!("cycle-tracker-start: fp_pow7_total");

        let x2 = self.mul(self);
        let x4 = x2.mul(x2);
        let x6 = x4.mul(x2);
        let out = x6.mul(self);

        std::println!("cycle-tracker-end: fp_pow7_total");

        out
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        Encoding::to_be_bytes(&self.0)
    }

    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Fp(<U256 as Encoding>::from_be_bytes(bytes))
    }

    pub fn to_u256(self) -> U256 {
        self.0
    }

    pub fn to_decimal_string(self) -> String {
        let bytes = self.0.to_be_bytes();
        let mut digits: Vec<u8> = vec![0];

        for byte in bytes {
            let mut carry = byte as u16;

            for digit in digits.iter_mut().rev() {
                let value = (*digit as u16) * 256 + carry;
                *digit = (value % 10) as u8;
                carry = value / 10;
            }

            while carry > 0 {
                digits.insert(0, (carry % 10) as u8);
                carry /= 10;
            }
        }

        digits.into_iter().map(|d| char::from(b'0' + d)).collect()
    }
}

impl fmt::Display for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_decimal_string())
    }
}

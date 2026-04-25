use crate::fp::Fp;
use crate::params::{FULL_ROUNDS, MDS, RATE, ROUND_CONSTANTS, WIDTH};

pub struct Sponge {
    state: [Fp; WIDTH],
}

impl Sponge {
    pub fn new() -> Self {
        std::println!("cycle-tracker-start: sp1_poseidon_new");
        let out = Self {
            state: [Fp::ZERO; WIDTH],
        };
        std::println!("cycle-tracker-end: sp1_poseidon_new");
        out
    }

    fn add_round_constants(&mut self, round: usize) {
        for i in 0..WIDTH {
            self.state[i] = self.state[i].add(ROUND_CONSTANTS[round][i]);
        }
    }

    fn sbox(&mut self) {
        for i in 0..WIDTH {
            self.state[i] = self.state[i].pow7();
        }
    }

    // MDS: 9 mul + 6 add
    fn mds(&mut self) {
        std::println!("cycle-tracker-start: sp1_mds_total");

        let s = self.state;

        for row in 0..WIDTH {
            self.state[row] = (0..WIDTH).fold(Fp::ZERO, |acc, col| {
                let product = MDS[row][col].mul(s[col]);
                let out = acc.add(product);

                out
            });
        }

        std::println!("cycle-tracker-end: sp1_mds_total");
    }

    pub fn permute(&mut self) {
        std::println!("cycle-tracker-start: sp1_poseidon_permute_total");

        for round in 0..FULL_ROUNDS {
            for i in 0..WIDTH {
                self.state[i] = self.state[i].pow7();
            }

            std::println!("cycle-tracker-start: sp1_apply_mds_total");

            let s = self.state;

            for row in 0..WIDTH {
                let m0 = MDS[row][0].mul(s[0]);
                let m1 = MDS[row][1].mul(s[1]);
                let m2 = MDS[row][2].mul(s[2]);

                let a0 = m0.add(m1);
                self.state[row] = a0.add(m2);

                self.state[row] = self.state[row].add(ROUND_CONSTANTS[round][row]);
            }

            std::println!("cycle-tracker-end: sp1_apply_mds_total");
        }

        std::println!("cycle-tracker-end: sp1_poseidon_permute_total");
    }

    pub fn absorb(&mut self, inputs: &[Fp]) {
        std::println!("cycle-tracker-start: sp1_poseidon_absorb_total");

        for chunk in inputs.chunks(RATE) {
            for (i, &x) in chunk.iter().enumerate() {
                self.state[i] = self.state[i].add(x);
            }

            self.permute();
        }

        std::println!("cycle-tracker-end: sp1_poseidon_absorb_total");
    }

    pub fn squeeze(&self) -> Fp {
        std::println!("cycle-tracker-start: sp1_poseidon_squeeze");
        let out = self.state[0];
        std::println!("cycle-tracker-end: sp1_poseidon_squeeze");
        out
    }

    pub fn hash_pair(left: Fp, right: Fp) -> Fp {
        std::println!("cycle-tracker-start: sp1_poseidon_hash_pair_total");

        let mut s = Self::new();
        s.absorb(&[left, right]);

        let out = s.squeeze();

        std::println!("cycle-tracker-end: sp1_poseidon_hash_pair_total");

        out
    }

    pub fn hash(inputs: &[Fp]) -> Fp {
        std::println!("cycle-tracker-start: sp1_poseidon_hash_total");

        let mut s = Self::new();

        if inputs.is_empty() {
            s.permute();
        } else {
            s.absorb(inputs);
        }

        let out = s.squeeze();

        std::println!("cycle-tracker-end: sp1_poseidon_hash_total");

        out
    }
}

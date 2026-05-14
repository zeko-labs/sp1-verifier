use sp1_build::build_program_with_args;

fn main() {
    build_program_with_args("../program/settlement", Default::default());
    build_program_with_args("../program/bridge", Default::default());
}

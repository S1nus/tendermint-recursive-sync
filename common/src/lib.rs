use tendermint_light_client_verifier::types::LightBlock;
use serde::{Serialize, Deserialize};
use p3_baby_bear::BabyBear;

#[derive(Serialize, Deserialize)]
pub enum ProgramInput {
    Recursive(RecursiveProgramInput),
    Genesis {
        hash: Vec<u8>,
        header: LightBlock,
        vkey: [u8; 32],
    }
}

#[derive(Serialize, Deserialize)]
pub struct RecursiveProgramInput {
    pub public_values: Vec<u8>,
    pub genesis_hash: Vec<u8>,
    pub recursive_proof_input: RecursiveProofInput,

    pub previous_header: LightBlock,
    pub current_header: LightBlock,

    pub current_vkey: [BabyBear; 8],
    pub previous_vkey: [BabyBear; 8],
}

#[derive(Serialize, Deserialize)]
pub enum RecursiveProofInput {
    Sp1, // proof itself is passed via write_proof
    Groth16 {
        proof: Vec<u8>,
        sp1_key: Vec<u8>,
    }
}

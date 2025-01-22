//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_verifier::Groth16Verifier;

use sha2::{Sha256, Digest};
mod buffer;
use buffer::Buffer;
use core::time::Duration;
use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};
use cryptographic_sync_common::{ProgramInput, RecursiveProofInput, RecursiveProgramInput};

const SP1_KEY : &[u8] = include_bytes!("../../../../.sp1/circuits/v3.0.0-rc1/groth16_vk.bin");

// Hash of `/program/elf/riscv32im-succinct-zkvm-elf_v1`
const ELF_V1_VK : [u8; 32] = [64, 236, 234, 171, 17, 201, 105, 176, 3, 100, 213, 186, 18, 94, 168, 150, 71, 88, 254, 193, 103, 254, 214, 117, 118, 231, 34, 17, 64, 79, 112, 21];

// INPUTS:
// verifying key
// public values
// genesis hash
// previous header
// current header

// COMMITS
// vk hash
// genesis hash
// current header hash
// `true`
//
//

//sp1_zkvm::lib::utils::words_to_bytes_le;

pub fn main() {
    let serialized_input = sp1_zkvm::io::read_vec();
    let input : ProgramInput = serde_cbor::from_slice(&serialized_input).expect("couldn't deserialize input");

    let recursive_input = match input {
        ProgramInput::Recursive(input) => input,
        ProgramInput::Genesis { hash, header }  => {
            if header.signed_header.header().hash().as_bytes() == hash {
                sp1_zkvm::io::commit(&true);
                return;
            } else {
                panic!("expected header == genesis hash");
            }
        }
    };

    let hash_of_current_vkey = Sha256::digest(&recursive_input.current_vkey);
    // commit verification key of the currently running program 
    sp1_zkvm::io::commit_slice(&hash_of_current_vkey);

    let hash_of_public_values = Sha256::digest(&recursive_input.public_values);
    let mut public_values_buffer = Buffer::from(&recursive_input.public_values);

    sp1_zkvm::io::commit_slice(&recursive_input.genesis_hash);
    // commit hash of the header being proved
    sp1_zkvm::io::commit_slice(&recursive_input.current_header.signed_header.header().hash().as_bytes());

    let hash_of_proof_vkey : Vec<u8> = public_values_buffer.read();
    let proof_vkey = if *hash_of_proof_vkey == *hash_of_current_vkey {
        // previous proof has the same vkey
        recursive_input.current_vkey
    } else if *hash_of_proof_vkey == ELF_V1_VK { 
        // vk hash of previous proof matches hardcoded vk, so verifying that we got passed the
        // correct key shouldn't be necessary
        recursive_input.previous_vkey
    } else {
        panic!("vkey of proof is not one of the allowed vkeys");
    };

    let proof_genesis_hash : Vec<u8> = public_values_buffer.read();
    if proof_genesis_hash != recursive_input.genesis_hash {
        panic!("invalid genesis");
    }

    let proven_header_hash : Vec<u8>  = public_values_buffer.read();
    if proven_header_hash != recursive_input.previous_header.signed_header.header().hash().as_bytes() {
        panic!("proven hash doesn't match previous header hash");
    }

    let last_result: bool = public_values_buffer.read();
    if !last_result {
        panic!("previous proof invalid");
    }

    match recursive_input.recursive_proof_input {
        RecursiveProofInput::Sp1 => {
            sp1_zkvm::lib::verify::verify_sp1_proof(proof_vkey, &hash_of_public_values[0..32]);
        }
        RecursiveProofInput::Groth16(raw_proof) => {
            Groth16Verifier::verify(raw_proof, &recursive_input.public_values, proof_vkey, &SP1_KEY).expect("groth16 verification failed");
        }
    }

    println!("tendermint time");

    let RecursiveProgramInput {previous_header, current_header, ..} = recursive_input;

    // Perform Tendermint (Celestia consensus) verification
    let vp = ProdVerifier::default();
    let opt = Options {
        trust_threshold: Default::default(),
        // 2 week trusting period.
        trusting_period: Duration::from_secs(14 * 24 * 60 * 60),
        clock_drift: Default::default(),
    };
    let verify_time = current_header.time() + Duration::from_secs(20);
    let verdict = vp.verify_update_header(
        current_header.as_untrusted_state(),
        previous_header.as_trusted_state(),
        &opt,
        verify_time.unwrap(),
    );
    match verdict {
        Verdict::Success => {
            println!("consented");
            sp1_zkvm::io::commit(&true);
        },
        _ => {
            panic!("consensus verification failed!");
        }
    }
    println!("Exiting??");

    return;
}

    
fn old_main() {
    let groth_mode : bool = sp1_zkvm::io::read();
    let prev_vkey: [u32; 8] = sp1_zkvm::io::read();
    let byte_slice: &[u8] = unsafe {
        core::slice::from_raw_parts(prev_vkey.as_ptr() as *const u8, prev_vkey.len() * core::mem::size_of::<u32>())
    };
    let hash_of_previous_vkey = Sha256::digest(byte_slice);

    let vkey: [u32; 8] = sp1_zkvm::io::read();
    let byte_slice: &[u8] = unsafe {
        core::slice::from_raw_parts(vkey.as_ptr() as *const u8, vkey.len() * core::mem::size_of::<u32>())
    };
    let hash_of_vkey = Sha256::digest(byte_slice);
    sp1_zkvm::io::commit(&hash_of_vkey.to_vec()); /////////////////////////////////////

    let public_values: Vec<u8> = sp1_zkvm::io::read();
    let mut public_values_buffer = Buffer::from(&public_values);
    let public_values_digest = Sha256::digest(&public_values);

    let genesis_hash = sp1_zkvm::io::read_vec();
    sp1_zkvm::io::commit(&genesis_hash); /////////////////////////////////////

    let h1_bytes = sp1_zkvm::io::read_vec();
    let h2_bytes = sp1_zkvm::io::read_vec();
    let h1: Option<LightBlock> = serde_cbor::from_slice(&h1_bytes).expect("couldn't deserialize h1");
    let h2: LightBlock = serde_cbor::from_slice(&h2_bytes).expect("couldn't deserialize h2");

    // commit h2 hash
    sp1_zkvm::io::commit(&h2.signed_header.header().hash().as_bytes().to_vec()); /////////////////////////////////////

    let Some(h1) = h1 else {
        if h2.signed_header.header().hash().as_bytes() == genesis_hash {
            sp1_zkvm::io::commit(&true);
            return;
        } else {
            panic!("expected h2 == genesis hash");
        }
    };

    let mut use_prev_key = false;
    // Ensure that we are verifying a proof of the same circuit as ourself
    // or previous one
    let last_vkey_hash: Vec<u8> = public_values_buffer.read();
    //println!("[zk] {last_vkey_hash:?}, {hash_of_vkey:?}");
    if last_vkey_hash != hash_of_vkey.to_vec() {
        if last_vkey_hash != hash_of_previous_vkey.to_vec() {
            panic!("invalid vkey!");
        } 
        
        println!("[zk] using previous vkey");
        use_prev_key = true;
    }
    // Ensure that the previous proof has the same genesis hash as the current proof
    let last_genesis_hash: Vec<u8> = public_values_buffer.read();
    if last_genesis_hash != genesis_hash {
        panic!("invalid genesis!");
    }
    // Ensure that previous proof has the h2 hash as the current h1 hash
    let last_h2_hash: Vec<u8> = public_values_buffer.read();
    if last_h2_hash != h1.signed_header.header().hash().as_bytes() {
        panic!("invalid hashes!");
    }
    // Ensure that previous proof is valid
    let last_result: bool = public_values_buffer.read();
    if !last_result {
        panic!("previous proof invalid!");
    }

    println!("I'm going in");

    if groth_mode {
        let groth16_proof_bytes = sp1_zkvm::io::read_vec();
        let groth16_proof : Vec<u8> = serde_cbor::from_slice(&groth16_proof_bytes).expect("couldn't deserialise potential groth16");
        let vk: String = sp1_zkvm::io::read();
        let result = Groth16Verifier::verify(&groth16_proof, &public_values, &vk, &SP1_KEY).expect("groth verification failed");
    } else {
        let vk = if use_prev_key {
            &prev_vkey
        } else {
            &vkey
        };
        // Verify the previous recursion layer
        sp1_zkvm::lib::verify::verify_sp1_proof(vk, &public_values_digest.into());
    }

    println!("tendermint, do your thing");

    // Perform Tendermint (Celestia consensus) verification
    let vp = ProdVerifier::default();
    let opt = Options {
        trust_threshold: Default::default(),
        // 2 week trusting period.
        trusting_period: Duration::from_secs(14 * 24 * 60 * 60),
        clock_drift: Default::default(),
    };
    let verify_time = h2.time() + Duration::from_secs(20);
    let verdict = vp.verify_update_header(
        h2.as_untrusted_state(),
        h1.as_trusted_state(),
        &opt,
        verify_time.unwrap(),
    );
    match verdict {
        Verdict::Success => {
            println!("consented");
            sp1_zkvm::io::commit(&true);
        },
        _ => {
            panic!("consensus verification failed!");
        }
    }
    println!("Exiting??");

    return;
}

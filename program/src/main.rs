//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_verifier::Groth16Verifier;

use sha2::{Sha256, Digest};
mod buffer;
use buffer::Buffer;
use core::time::Duration;
use tendermint_light_client_verifier::{
    options::Options, ProdVerifier, Verdict, Verifier,
};
use cryptographic_sync_common::{ProgramInput, RecursiveProofInput, RecursiveProgramInput};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeField32, AbstractField, PrimeField};
use p3_bn254_fr::Bn254Fr;
use sp1_zkvm::lib::utils::{words_to_bytes_le};

// Hash of `/program/elf/riscv32im-succinct-zkvm-elf_v1`
const ELF_V1_VK : [u8; 32] = [222, 215, 35, 141, 194, 206, 15, 217, 145, 121, 241, 60, 245, 122, 175, 253, 15, 85, 12, 97, 165, 31, 205, 255, 76, 65, 65, 223, 72, 62, 189, 167];

// COMMITS
// sha256(vk)
// genesis hash
// current header hash
// verification result (true)

#[sp1_derive::cycle_tracker]
fn babybears_to_u32(hash: &[BabyBear; 8]) -> [u32; 8] {
    hash
        .iter()
        .map(|n| n.as_canonical_u32())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

//https://github.com/succinctlabs/sp1/blob/2aed8fea16a67a5b2983ffc471b2942c2f2512c8/crates/prover/src/utils.rs#L122C1-L133C2
/// Convert 8 BabyBear words into a Bn254Fr field element by shifting by 31 bits each time. The last
/// word becomes the least significant bits.
#[sp1_derive::cycle_tracker]
pub fn babybears_to_bn254(digest: &[BabyBear; 8]) -> Bn254Fr {
    let mut result = Bn254Fr::zero();
    for word in digest.iter() {
        // Since BabyBear prime is less than 2^31, we can shift by 31 bits each time and still be
        // within the Bn254Fr field, so we don't have to truncate the top 3 bits.
        result *= Bn254Fr::from_canonical_u64(1 << 31);
        result += Bn254Fr::from_canonical_u32(word.as_canonical_u32());
    }
    result
}

pub fn main() {
    println!("cycle-tracker-start: wholeshebang");

    println!("cycle-tracker-start: input");
    let serialized_input = sp1_zkvm::io::read_vec();
    let input : ProgramInput = serde_cbor::from_slice(&serialized_input).expect("couldn't deserialize input");
    println!("cycle-tracker-end: input");

    println!("cycle-tracker-start: post-input");
    let recursive_input = match input {
        ProgramInput::Recursive(input) => input,
        ProgramInput::Genesis { hash, header, vkey }  => {
            if header.signed_header.header().hash().as_bytes() == hash {
                let sha256_of_vkey = Sha256::digest(&vkey);
                println!("vk: {sha256_of_vkey:?}");
                sp1_zkvm::io::commit(&sha256_of_vkey.to_vec());
                sp1_zkvm::io::commit(&hash);
                sp1_zkvm::io::commit(&hash);
                sp1_zkvm::io::commit(&true);
                println!("cycle-tracker-end: post-input");
                println!("cycle-tracker-end: wholeshebang");
                return;
            } else {
                panic!("expected header == genesis hash");
            }
        }
    };
    println!("cycle-tracker-end: post-input");

    println!("cycle-tracker-start: debear");
    let current_vkey_hash_u32 = babybears_to_u32(&recursive_input.current_vkey);
    println!("cycle-tracker-end: debear");

    let sha256_of_current_vkey_hash = Sha256::digest(words_to_bytes_le(&current_vkey_hash_u32[..]));
    // commit verification key of the currently running program 
    sp1_zkvm::io::commit(&sha256_of_current_vkey_hash.to_vec());
    println!("vk: {sha256_of_current_vkey_hash:?}");

    let hash_of_public_values = Sha256::digest(&recursive_input.public_values);
    let mut public_values_buffer = Buffer::from(&recursive_input.public_values);

    sp1_zkvm::io::commit(&recursive_input.genesis_hash);
    // commit hash of the header being proved
    sp1_zkvm::io::commit(&recursive_input.current_header.signed_header.header().hash().as_bytes().to_vec());

    let hash_of_proof_vkey : Vec<u8> = public_values_buffer.read();

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

    println!("cycle-tracker-start: recursive");
    match recursive_input.recursive_proof_input {
        RecursiveProofInput::Sp1 => {
            let proof_vkey_hash = if *hash_of_proof_vkey == *sha256_of_current_vkey_hash {
                // previous proof has the same vkey
                current_vkey_hash_u32
            } else if *hash_of_proof_vkey == ELF_V1_VK { 
                // vk hash of previous proof matches hardcoded vk, so verifying that we got passed the
                // correct key shouldn't be necessary
                babybears_to_u32(&recursive_input.previous_vkey)
            } else {
                panic!("verify sp1: vkey of proof is not one of the allowed vkeys");
            };

            sp1_zkvm::lib::verify::verify_sp1_proof(&proof_vkey_hash, &hash_of_public_values.into());
        }
        RecursiveProofInput::Groth16 { proof, sp1_key } => {
            let proof_vkey_hash = if *hash_of_proof_vkey == *sha256_of_current_vkey_hash {
                // previous proof has the same vkey
                recursive_input.current_vkey
            } else if *hash_of_proof_vkey == ELF_V1_VK { 
                // vk hash of previous proof matches hardcoded vk, so verifying that we got passed the
                // correct key shouldn't be necessary
                recursive_input.previous_vkey
            } else {
                panic!("verify groth16: vkey of proof is not one of the allowed vkeys");
            };

            // https://docs.rs/sp1-prover/3.0.0-rc1/src/sp1_prover/types.rs.html#56
            let vkey_digest_bn254 = babybears_to_bn254(&proof_vkey_hash);
            let vkey_digest_bytes32 = format!("0x{:0>64}", vkey_digest_bn254.as_canonical_biguint().to_str_radix(16));
            Groth16Verifier::verify(&proof, &recursive_input.public_values, &vkey_digest_bytes32, &sp1_key).expect("groth16 verification failed");
        }
    }
    println!("cycle-tracker-end: recursive");

    println!("cycle-tracker-start: tendermint");
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
    println!("cycle-tracker-end: tendermint");

    println!("cycle-tracker-end: wholeshebang");

    return;
}

/*
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
*/

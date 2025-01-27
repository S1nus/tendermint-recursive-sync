//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_verifier::Groth16Verifier;

use core::time::Duration;
use cryptographic_sync_common::{Buffer, ProgramInput, RecursiveProgramInput, RecursiveProofInput};
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::{AbstractField, PrimeField, PrimeField32};
use sha2::{Digest, Sha256};
use sp1_zkvm::lib::utils::words_to_bytes_le;
use tendermint_light_client_verifier::{options::Options, ProdVerifier, Verdict, Verifier};

// `/program/elf/riscv32im-succinct-zkvm-elf_v1`
const ELF_V1_VK: [u8; 32] = [
    222, 215, 35, 141, 194, 206, 15, 217, 145, 121, 241, 60, 245, 122, 175, 253, 15, 85, 12, 97,
    165, 31, 205, 255, 76, 65, 65, 223, 72, 62, 189, 167,
];

// COMMITS
// sha256(vk)
// genesis hash
// current header hash
// verification result (true)

#[sp1_derive::cycle_tracker]
fn babybears_to_u32(hash: &[BabyBear; 8]) -> [u32; 8] {
    hash.iter()
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
    let input: ProgramInput =
        serde_cbor::from_slice(&serialized_input).expect("couldn't deserialize input");
    println!("cycle-tracker-end: input");

    println!("cycle-tracker-start: post-input");
    let recursive_input = match input {
        ProgramInput::Recursive(input) => input,
        ProgramInput::Genesis { hash, header, vkey } => {
            if header.signed_header.header().hash().as_bytes() == hash {
                let sha256_of_vkey = Sha256::digest(&words_to_bytes_le(&vkey));
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
    sp1_zkvm::io::commit(
        &recursive_input
            .current_header
            .signed_header
            .header()
            .hash()
            .as_bytes()
            .to_vec(),
    );

    let hash_of_proof_vkey: Vec<u8> = public_values_buffer.read();

    let proof_genesis_hash: Vec<u8> = public_values_buffer.read();
    if proof_genesis_hash != recursive_input.genesis_hash {
        panic!("invalid genesis");
    }

    let proven_header_hash: Vec<u8> = public_values_buffer.read();
    if proven_header_hash
        != recursive_input
            .previous_header
            .signed_header
            .header()
            .hash()
            .as_bytes()
    {
        panic!("proven hash doesn't match previous header hash");
    }

    let last_result: bool = public_values_buffer.read();
    if !last_result {
        panic!("previous proof invalid");
    }

    println!("cycle-tracker-start: recursive");
    match recursive_input.recursive_proof_input {
        RecursiveProofInput::Sp1 => {
            let proof_vkey_hash = recursive_input
                .proof_vkey_override
                .as_ref()
                .map(babybears_to_u32)
                .unwrap_or(current_vkey_hash_u32);

            sp1_zkvm::lib::verify::verify_sp1_proof(
                &proof_vkey_hash,
                &hash_of_public_values.into(),
            );
        }
        RecursiveProofInput::Groth16 { proof, sp1_key } => {
            let proof_vkey_hash = recursive_input
                .proof_vkey_override
                .unwrap_or(recursive_input.current_vkey);

            // https://docs.rs/sp1-prover/3.0.0-rc1/src/sp1_prover/types.rs.html#56
            let vkey_digest_bn254 = babybears_to_bn254(&proof_vkey_hash);
            let vkey_digest_bytes32 = format!(
                "0x{:0>64}",
                vkey_digest_bn254.as_canonical_biguint().to_str_radix(16)
            );
            Groth16Verifier::verify(
                &proof,
                &recursive_input.public_values,
                &vkey_digest_bytes32,
                &sp1_key,
            )
            .expect("groth16 verification failed");
        }
    }
    println!("cycle-tracker-end: recursive");

    println!("cycle-tracker-start: tendermint");
    let RecursiveProgramInput {
        previous_header,
        current_header,
        ..
    } = recursive_input;

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
        }
        _ => {
            panic!("consensus verification failed!");
        }
    }
    println!("cycle-tracker-end: tendermint");

    println!("cycle-tracker-end: wholeshebang");

    return;
}

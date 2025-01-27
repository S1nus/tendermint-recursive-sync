use std::fs::{self, File};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use cryptographic_sync_common::{Buffer, ProgramInput, RecursiveProgramInput, RecursiveProofInput};
use serde_json;
use sha2::{Digest, Sha256};
use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};
use tendermint_light_client_verifier::types::LightBlock;

mod tm_rpc_types;
mod tm_rpc_utils;

use tm_rpc_utils::TendermintRPCClient;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");
const PREV_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf_v1");

const SP1_GROTH16_VK_V3_0_0: &[u8] = include_bytes!("../groth16_vk-3.0.0-rc1.bin");

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    unproven_height: u64,
    proof: Option<PathBuf>,
    #[arg(long, default_value = "header_cache")]
    header_cache_dir: PathBuf,
    #[arg(long, default_value_t = false)]
    groth16: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Sp1 { proof_path: PathBuf },
    Groth16 { proof_path: PathBuf },
    Genesis,
}

async fn get_cache_or_fetch(
    height: u64,
    client: &TendermintRPCClient,
    cache_dir: &Path,
) -> LightBlock {
    let cached_header_path = cache_dir.join(format!("{height}.json"));
    if let Ok(cached_file) = File::open(&cached_header_path) {
        return serde_json::from_reader(cached_file).expect("could not parse cached header");
    };

    println!("Fetching {height}");

    let peer_id = client.fetch_peer_id().await.unwrap();
    let header = client.fetch_light_block(height, peer_id).await.unwrap();

    let cache_file = File::create(cached_header_path).expect("could not create header cache");
    serde_json::to_writer(cache_file, &header).expect("could not cache serialized header");

    header
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let client = tm_rpc_utils::TendermintRPCClient::default();
    let genesis = get_cache_or_fetch(1, &client, cli.header_cache_dir.as_ref()).await;

    sp1_sdk::utils::setup_logger();
    let mut stdin = SP1Stdin::new();

    let prover_client = ProverClient::new();
    let (_, prev_vk) = prover_client.setup(PREV_ELF);
    let (pk, vk) = prover_client.setup(ELF);

    println!("PREV = {:?}", prev_vk.hash_bytes());
    println!("VK   = {:?}", vk.hash_bytes());

    let program_input = if cli.unproven_height == 1 {
        ProgramInput::Genesis {
            hash: genesis.signed_header.header().hash().as_bytes().to_vec(),
            header: genesis,
            vkey: vk.hash_u32(),
        }
    } else {
        let proof_path = cli.proof.expect("missing proof for previous header");
        let proof_file = File::open(proof_path).expect("could not open proof file");

        let proof_with_public_values: SP1ProofWithPublicValues =
            serde_json::from_reader(proof_file).expect("could not parse proof");

        let vk_le: Vec<_> = vk
            .hash_u32()
            .into_iter()
            .flat_map(|i| i.to_le_bytes())
            .collect();
        let prev_vk_le: Vec<_> = prev_vk
            .hash_u32()
            .into_iter()
            .flat_map(|i| i.to_le_bytes())
            .collect();
        let current_vk_digest = Sha256::digest(&vk_le);
        let previous_vk_digest = Sha256::digest(&prev_vk_le);
        println!("current hash = {:?}", current_vk_digest);
        println!("previous hash = {:?}", previous_vk_digest);

        let mut public_values = Buffer::from(&proof_with_public_values.public_values.as_slice());
        let proof_vkey_digest: Vec<u8> = public_values.read();
        println!("public values vkey = {:?}", proof_vkey_digest);

        let proof_vkey_override = if *proof_vkey_digest == *previous_vk_digest {
            Some(prev_vk.hash_babybear())
        } else if *proof_vkey_digest == *current_vk_digest {
            None
        } else {
            panic!("proof vkey is not one of the expected ones. regenerate proofs?");
        };

        let proof_input = match proof_with_public_values.proof {
            // default mode for moving forward, since it's more performant
            SP1Proof::Compressed(p) => {
                if proof_vkey_override.is_some() {
                    stdin.write_proof(*p, prev_vk.vk);
                } else {
                    stdin.write_proof(*p, vk.vk.clone());
                }
                RecursiveProofInput::Sp1
            }
            // groth16 is used for upgrades (so we use previous vk)
            SP1Proof::Groth16(_) => RecursiveProofInput::Groth16 {
                proof: proof_with_public_values.bytes(),
                sp1_key: SP1_GROTH16_VK_V3_0_0.to_vec(),
            },
            _ => unimplemented!("unsupported proof type"),
        };

        let proven_header = get_cache_or_fetch(
            cli.unproven_height - 1,
            &client,
            cli.header_cache_dir.as_ref(),
        )
        .await;
        let unproven_header =
            get_cache_or_fetch(cli.unproven_height, &client, cli.header_cache_dir.as_ref()).await;

        ProgramInput::Recursive(RecursiveProgramInput {
            public_values: proof_with_public_values.public_values.to_vec(),
            genesis_hash: genesis.signed_header.header().hash().as_bytes().to_vec(),
            recursive_proof_input: proof_input,
            previous_header: proven_header,
            current_header: unproven_header,
            current_vkey: vk.hash_babybear(),
            proof_vkey_override,
        })
    };

    let serialized_input =
        serde_cbor::to_vec(&program_input).expect("failed to serialise program input");
    stdin.write_vec(serialized_input);

    let proof = prover_client.prove(&pk, stdin);
    if cli.groth16 {
        let groth16_proof = proof.groth16().run().expect("could not prove");

        fs::write(
            format!("{}_groth16_proof.json", cli.unproven_height),
            serde_json::to_string(&groth16_proof).expect("could not json serialize"),
        )
        .expect("could not write");
    } else {
        let sp1_proof = proof.compressed().run().expect("could not prove");
        println!(
            "writing key: {:?}",
            sp1_proof
                .proof
                .try_as_compressed_ref()
                .unwrap()
                .vk
                .hash_bytes()
        );

        fs::write(
            format!("{}_proof.json", cli.unproven_height),
            serde_json::to_string(&sp1_proof).expect("could not json serialize"),
        )
        .expect("could not write");
    }
    println!("the vkey: {:?}", vk.vk);

    return Ok(());
}

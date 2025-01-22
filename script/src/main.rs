use std::fs::{self, File};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::{io::Write, path::Path};

use clap::{Parser, Subcommand};
use cryptographic_sync_common::{RecursiveProofInput, RecursiveProgramInput, ProgramInput};
use serde_json;
use sp1_sdk::{HashableKey, SP1VerifyingKey};
use sp1_sdk::{ProverClient, SP1Stdin};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};

mod tm_rpc_types;
mod tm_rpc_utils;

use tm_rpc_utils::TendermintRPCClient;

pub const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");
pub const PREV_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf_v1");

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    unproven_height: u64,
    proof: Option<PathBuf>,
    #[arg(long, default_value = "header_cache")]
    header_cache_dir: PathBuf,
    //#[command(subcommand)] command: Commands,
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

    let mut stdin = SP1Stdin::new();

    let prover_client = ProverClient::new();
    let (_, prev_vk) = prover_client.setup(PREV_ELF);
    let (pk, vk) = prover_client.setup(ELF);

    println!("= {:?}", prev_vk.hash_bytes());

    let program_input = if cli.unproven_height == 1 {
        ProgramInput::Genesis {
            hash: genesis.signed_header.header().hash().as_bytes().to_vec(),
            header: genesis,
        }
    } else {
        let proof_path = cli.proof.expect("missing proof for previous header");
        let proof_file = File::open(proof_path).expect("could not open proof file");

        let SP1ProofWithPublicValues {
            proof,
            public_values,
            ..
        } = serde_json::from_reader(proof_file).expect("could not parse proof");

        let proven_header = get_cache_or_fetch(
            cli.unproven_height - 1,
            &client,
            cli.header_cache_dir.as_ref(),
        )
        .await;
        let unproven_header =
            get_cache_or_fetch(cli.unproven_height, &client, cli.header_cache_dir.as_ref()).await;

        let proof_input = match proof {
            // default mode for moving forward, since it's more performant
            SP1Proof::Compressed(p) => {
                stdin.write_proof(*p, prev_vk.vk);
                RecursiveProofInput::Sp1
            }
            // groth16 is used for upgrades (so we use previous vk)
            SP1Proof::Groth16(p) => {
                ProgramInput::Groth16(p.raw_proof)

                todo!()
            }
            _ => unimplemented!("unsupported proof type"),
        };

        ProgramInput::Recursive(RecursiveProgramInput {
            public_values: public_values.to_vec(),
            genesis_hash: genesis.signed_header.header().hash().as_bytes().to_vec(),
            recursive_proof_input: proof_input,
            previous_header: proven_header,
            current_header: unproven_header,
            current_vkey: vk.hash_bytes(),
            previous_vkey: prev_vk.hash_bytes(),
        })
    };

    let serialized_input =
        serde_cbor::to_vec(&program_input).expect("failed to serialise program input");
    stdin.write_vec(serialized_input);


    return Ok(()); 
    /*
    match cli.command {
        Commands::Sp1 { proof_path } => {
            let proof_file = File::open(proof_path).expect("could not open proof file");
        }
        _ => todo!()
    }
    */

    println!("creating rpc client");
    let peer_id = client.fetch_peer_id().await.unwrap();
    println!("getting genesis...");
    //let genesis = client.fetch_light_block(1, peer_id).await.unwrap();
    let genesis = get_cache_or_fetch(1, &client, cli.header_cache_dir.as_ref()).await;

    let next = 2341561;

    let left_off_proof_file =
        File::open("2341560_proof.json").expect("could not open left_off_proof.json");
    let mut running_proof: SP1ProofWithPublicValues =
        serde_json::from_reader(left_off_proof_file).expect("could not parse");

    let running_header_file = File::open("needed_headers/2341560.json").unwrap();
    let mut running_head: Option<LightBlock> =
        serde_json::from_reader(running_header_file).unwrap();

    // header where i got booted off wifi
    let left_off: String = "2341560".to_string();

    let next_light_block = client.fetch_light_block(next, peer_id).await.unwrap();
    println!("Fetched {}", next_light_block.signed_header.header.height);

    let maybe_groth16_proof = if let Ok(groth_proof_file) = File::open("2341561_groth16_proof.json")
    {
        println!("GROTH16 MODE");
        let proof: SP1ProofWithPublicValues =
            serde_json::from_reader(groth_proof_file).expect("could not parse");
        //let groth_proof = proof.proof.try_as_groth_16().expect("groth proof");
        //Some(groth_proof.raw_proof.as_bytes())
        Some(proof)
    } else {
        None
    };

    let prover_client = ProverClient::new();
    let (_, prev_vk) = prover_client.setup(PREV_ELF);
    let (pk, vk) = prover_client.setup(ELF);
    let running_proof_public_values = running_proof.public_values.to_vec();

    let mut stdin = SP1Stdin::new();
    stdin.write(&maybe_groth16_proof.is_some());
    stdin.write(&prev_vk.hash_u32());
    stdin.write(&vk.hash_u32());
    if let Some(proof) = &maybe_groth16_proof {
        stdin.write(&proof.public_values.to_vec());
    } else {
        stdin.write(&running_proof_public_values);
    }
    stdin.write_vec(
        genesis
            .clone()
            .signed_header
            .header()
            .hash()
            .as_bytes()
            .to_vec(),
    );
    let encoded1 = serde_cbor::to_vec(&running_head).expect("failed to serialise running head");
    stdin.write_vec(encoded1);
    let next_header: Option<LightBlock> = Some(next_light_block);

    let encoded2 = serde_cbor::to_vec(&next_header).expect("coudl not serialize");
    stdin.write_vec(encoded2);
    let running_proof_inner = *match running_proof.proof.clone() {
        SP1Proof::Compressed(c) => c,
        _ => panic!("Not the right kind of SP1 proof"),
    };
    stdin.write_proof(running_proof_inner, prev_vk.vk.clone());
    println!("creating proof for {}", next);

    if let Some(groth_proof) = maybe_groth16_proof {
        let groth_proof = groth_proof.proof.try_as_groth_16().expect("groth proof");
        let encoded_groth = serde_cbor::to_vec(&groth_proof.raw_proof.as_bytes())
            .expect("failed to serialise groth16");
        stdin.write_vec(encoded_groth);
        stdin.write(&vk.bytes32())
    } else {
        //let encoded_groth = serde_cbor::to_vec(&None::<Groth16Bn254Proof>).expect("failed to serialise groth16");
        //stdin.write_vec(encoded_groth);
        //stdin.write(&"");
    }

    running_proof = prover_client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .expect("could not prove");
    fs::write(
        format!("{}_groth16_proof.json", next),
        serde_json::to_string(&running_proof).expect("could not json serialize"),
    )
    .expect("could not write");
    println!("the vkey: {:?}", vk.vk);

    /*
    println!("lloop: {:?}", start..files.len());
    for i in start..files.len() {
        let prover_client = ProverClient::new();
        let (pk, vk) = prover_client.setup(ELF);
        let running_proof_public_values = running_proof.public_values.to_vec();
        let mut stdin = SP1Stdin::new();
        stdin.write(&vk.hash_u32());
        stdin.write(&running_proof_public_values);
        stdin.write_vec(
            genesis
                .clone()
                .signed_header
                .header()
                .hash()
                .as_bytes()
                .to_vec(),
        );
        let encoded1 = serde_cbor::to_vec(&running_head).expect("failed to serialzie running head");
        stdin.write_vec(encoded1);
        let next_header_file = File::open(format!("needed_headers/{}.json", &files[i]))
            .expect("Could not open");
        let next_header: Option<LightBlock> =
            Some(serde_json::from_reader(next_header_file).expect("could not parse"));
        let encoded2 = serde_cbor::to_vec(&next_header).expect("coudl not serialize");
        stdin.write_vec(encoded2);
        let running_proof_inner = *match running_proof.proof.clone() {
            SP1Proof::Compressed(c) => c,
            _ => panic!("Not the right kind of SP1 proof"),
        };
        stdin.write_proof(running_proof_inner, vk.vk.clone());
        println!("creating proof for {}", files[i]);
        running_proof = prover_client
            .prove(&pk, stdin)
            .groth16()
            .run()
            .expect("could not prove");
        fs::write(
            format!("{}_groth16_proof.json", files[i]),
            serde_json::to_string(&running_proof).expect("could not json serialize"),
        )
        .expect("could not write");
        println!("the vkey: {:?}", vk.vk);
        return Ok(());
        running_head = next_header;
    }
    */
    Ok(())
}

use std::fs;
use std::fs::File;
use std::io::Write;
use alloy_provider::ReqwestProvider;
use clap::Parser;
use reth_primitives::B256;
use rsp_client_executor::{
    io::ClientExecutorInput, ChainVariant, CHAIN_ID_ETH_MAINNET, CHAIN_ID_LINEA_MAINNET,
    CHAIN_ID_OP_MAINNET, CHAIN_ID_HEMI_TESTNET, CHAIN_ID_HEMI_MAINNET,
};
use rsp_host_executor::HostExecutor;
use sp1_sdk::{ProverClient, SP1Stdin, SP1VerifyingKey};
use std::path::PathBuf;
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

mod execute;

mod cli;
use cli::ProviderArgs;
use crate::execute::process_execution_report;

/// The arguments for the host executable.
#[derive(Debug, Clone, Parser)]
struct HostArgs {
    /// The starting block number of the block to execute.
    #[clap(long)]
    lhs_block_number: u64,
    /// The ending block number of the block to execute.
    #[clap(long)]
    rhs_block_number: u64,
    #[clap(flatten)]
    provider: ProviderArgs,
    /// Whether to generate a proof or just execute the block.
    #[clap(long)]
    prove: bool,
    /// Optional path to the directory containing cached client input. A new cache file will be
    /// created from RPC data if it doesn't already exist.
    #[clap(long)]
    cache_dir: Option<PathBuf>,
    #[clap(long, default_value = "report.csv")]
    report_path: PathBuf,
    /// Whether to save proofs.
    #[clap(long)]
    save_proof: bool
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Intialize the environment variables.
    dotenv::dotenv().ok();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    // Initialize the logger.
    tracing_subscriber::registry().with(fmt::layer()).with(EnvFilter::from_default_env()).init();

    // Parse the command line arguments.
    let args = HostArgs::parse();
    let provider_config = args.provider.into_provider().await?;

    let variant = match provider_config.chain_id {
        CHAIN_ID_ETH_MAINNET => ChainVariant::Ethereum,
        CHAIN_ID_OP_MAINNET => ChainVariant::Optimism,
        CHAIN_ID_LINEA_MAINNET => ChainVariant::Linea,
        CHAIN_ID_HEMI_TESTNET => ChainVariant::HemiTestnet,
        CHAIN_ID_HEMI_MAINNET => ChainVariant::HemiMainnet,
        _ => {
            eyre::bail!("unknown chain ID: {}", provider_config.chain_id);
        }
    };

    let start_block = args.lhs_block_number;
    let end_block = args.rhs_block_number;

    // // Generate the proof.
    let client = ProverClient::new();

    // Setup the proving key and verification key.
    let (pk, vk) = client.setup(match variant {
        ChainVariant::Ethereum => {
            include_bytes!("../../client-eth/elf/riscv32im-succinct-zkvm-elf")
        }
        ChainVariant::Optimism => include_bytes!("../../client-op/elf/riscv32im-succinct-zkvm-elf"),
        ChainVariant::Linea => include_bytes!("../../client-linea/elf/riscv32im-succinct-zkvm-elf"),
        // change to hemi client
        ChainVariant::HemiTestnet => {
            include_bytes!("../../client-hemi/elf/riscv32im-succinct-zkvm-elf")
        }
        ChainVariant::HemiMainnet => {
            include_bytes!("../../client-hemi/elf/riscv32im-succinct-zkvm-elf")
        }
    });

    save_vk(&vk, "setup").expect("Failed to save verifying key");

    for block in start_block..=end_block {
        let provider_config = provider_config.clone();
        let client_input_from_cache = try_load_input_from_cache(
            args.cache_dir.as_ref(),
            provider_config.chain_id,
            block,
        )?;

        let client_input = match (client_input_from_cache, provider_config.rpc_url) {
            (Some(client_input_from_cache), _) => client_input_from_cache,
            (None, Some(rpc_url)) => {
                // Cache not found but we have RPC
                // Setup the provider.
                let provider = ReqwestProvider::new_http(rpc_url);

                // Setup the host executor.
                let host_executor = HostExecutor::new(provider);
                // Execute the host.
                let client_input = host_executor
                    .execute(block, variant)
                    .await
                    .unwrap();

                if let Some(ref cache_dir) = args.cache_dir {
                    let input_folder = cache_dir.join(format!("input/{}", provider_config.chain_id));
                    if !input_folder.exists() {
                        std::fs::create_dir_all(&input_folder)?;
                    }

                    let input_path = input_folder.join(format!("{}.bin", block));
                    let mut cache_file = std::fs::File::create(input_path)?;

                    bincode::serialize_into(&mut cache_file, &client_input)?;
                }

                client_input
            }
            (None, None) => {
                eyre::bail!("cache not found and RPC URL not provided")
            }
        };

        println!("Block post executed");

        // Execute the block inside the zkVM.
        let mut stdin = SP1Stdin::new();
        let buffer = bincode::serialize(&client_input).unwrap();
        stdin.write_vec(buffer);

        // Only execute the program.
        let (mut public_values, execution_report) =
            client.execute(&pk.elf, stdin.clone()).run().unwrap();

        // Read the block hash.
        let block_hash = public_values.read::<B256>();
        println!("success: block_hash={block_hash}, block_number:{block}");

        if args.prove {
            // Actually generate the proof. It is strongly recommended you use the network prover
            // given the size of these programs.
            println!("Starting proof generation.");
            let proof = client.prove(&pk, stdin).groth16().run().expect("Proving should work.");
            println!("Proof generation finished.");

            client.verify(&proof, &vk).expect("proof verification should succeed");

            if args.save_proof {
                let output_folder = PathBuf::from("proofs");
                if !output_folder.exists() {
                    fs::create_dir_all(&output_folder)?;
                }

                let proof_path = output_folder.join(format!("block-proof-{}.bin", block));
                proof.save(proof_path).expect("saving proof failed");
            }
        }
        let report_path = args.report_path.clone();
        process_execution_report(variant, client_input, execution_report, report_path)?;
    }

    Ok(())
}

fn try_load_input_from_cache(
    cache_dir: Option<&PathBuf>,
    chain_id: u64,
    block_number: u64,
) -> eyre::Result<Option<ClientExecutorInput>> {
    Ok(if let Some(cache_dir) = cache_dir {
        let cache_path = cache_dir.join(format!("input/{}/{}.bin", chain_id, block_number));

        if cache_path.exists() {
            // TODO: prune the cache if invalid instead
            let mut cache_file = std::fs::File::open(cache_path)?;
            let client_input: ClientExecutorInput = bincode::deserialize_from(&mut cache_file)?;

            Some(client_input)
        } else {
            None
        }
    } else {
        None
    })
}

pub fn save_vk(vk: &SP1VerifyingKey, folder: &str) ->eyre::Result<()> {
    let output_folder = PathBuf::from(folder);
    if !output_folder.exists() {
        fs::create_dir_all(&output_folder)?;
    }

    let file_path = output_folder.join("verifying_key.json");
    let vk_json = serde_json::to_string_pretty(vk)?;

    let mut file = File::create(file_path)?;
    file.write_all(vk_json.as_bytes())?;

    Ok(())
}

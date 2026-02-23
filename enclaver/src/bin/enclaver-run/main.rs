use anyhow::Result;
use clap::{Parser, Subcommand};
use enclaver::constants::{EIF_FILE_NAME, MANIFEST_FILE_NAME, RELEASE_BUNDLE_DIR};
use enclaver::manifest::load_manifest_raw;
use enclaver::nitro_cli::NitroCLI;
use enclaver::run::{Enclave, EnclaveExitStatus, EnclaveOpts};
use enclaver::utils;
use log::info;
use std::{
    path::PathBuf,
    process::{ExitCode, Termination},
};
use tokio::io::{AsyncWriteExt, stdout};
use tokio_util::sync::CancellationToken;

const ENCLAVE_SIGNALED_EXIT_CODE: u8 = 107;
const ENCLAVE_FATAL: u8 = 108;
const ENCLAVER_INTERRUPTED: u8 = 109;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(long, value_parser)]
    eif_file: Option<PathBuf>,

    #[clap(long, value_parser)]
    manifest_file: Option<PathBuf>,

    #[clap(long)]
    cpu_count: Option<i32>,

    #[clap(long)]
    memory_mb: Option<i32>,

    #[clap(long)]
    debug_mode: bool,

    #[clap(subcommand)]
    sub_command: Option<SubCommand>,

    #[clap(long = "verbose", short = 'v', action = clap::ArgAction::Count)]
    verbosity: u8,
}

#[derive(Debug, Subcommand)]
enum SubCommand {
    #[clap(name = "print-manifest")]
    PrintManifest,

    #[clap(name = "describe-eif")]
    DescribeEif,
}

enum CLISuccess {
    EnclaveStatus(EnclaveExitStatus),
    Ok,
}

impl Termination for CLISuccess {
    fn report(self) -> ExitCode {
        use CLISuccess::*;
        use EnclaveExitStatus::*;

        match self {
            EnclaveStatus(Exited(code)) => ExitCode::from(code as u8),
            EnclaveStatus(Signaled(_signal)) => ExitCode::from(ENCLAVE_SIGNALED_EXIT_CODE),
            EnclaveStatus(Fatal(_err)) => ExitCode::from(ENCLAVE_FATAL),
            EnclaveStatus(Cancelled) => ExitCode::from(ENCLAVER_INTERRUPTED),
            Ok => ExitCode::SUCCESS,
        }
    }
}

async fn run(args: Cli) -> Result<CLISuccess> {
    let shutdown_signal = enclaver::utils::register_shutdown_signal_handler().await?;

    let enclave = Enclave::new(EnclaveOpts {
        eif_path: args.eif_file,
        manifest_path: args.manifest_file,
        cpu_count: args.cpu_count,
        memory_mb: args.memory_mb,
        debug_mode: args.debug_mode,
    })
    .await?;

    let cancellation = CancellationToken::new();

    // Wait for the shutdown signal in a separate task. If the signal comes, cancel the
    // enclave run.
    let cancel_task = {
        let cancellation = cancellation.clone();
        utils::spawn!("shutdown handler", async move {
            shutdown_signal.await;
            cancellation.cancel();
            info!("shutdown signal received, terminating enclave");
        })?
    };

    let status = enclave.run(cancellation).await?;

    cancel_task.abort();
    _ = cancel_task.await;

    Ok(CLISuccess::EnclaveStatus(status))
}

async fn dump_manifest() -> Result<CLISuccess> {
    let manifest_path = PathBuf::from(RELEASE_BUNDLE_DIR).join(MANIFEST_FILE_NAME);
    let (raw_manifest, _) = load_manifest_raw(&manifest_path).await?;
    stdout().write_all(&raw_manifest).await?;

    Ok(CLISuccess::Ok)
}

async fn describe_eif() -> Result<CLISuccess> {
    let eif_path = PathBuf::from(RELEASE_BUNDLE_DIR).join(EIF_FILE_NAME);
    let cli = NitroCLI::new();
    let eif_info = cli.describe_eif(&eif_path).await?;
    let eif_info_bytes = serde_json::to_vec_pretty(&eif_info)?;
    stdout().write_all(&eif_info_bytes).await?;

    Ok(CLISuccess::Ok)
}

#[tokio::main]
async fn main() -> Result<CLISuccess> {
    let args = Cli::parse();
    enclaver::utils::init_logging(args.verbosity);

    #[cfg(feature = "tracing")]
    console_subscriber::ConsoleLayer::builder()
        .with_default_env()
        .server_addr(([0, 0, 0, 0], 51001))
        .init();

    match args.sub_command {
        None => run(args).await,
        Some(SubCommand::PrintManifest) => dump_manifest().await,
        Some(SubCommand::DescribeEif) => describe_eif().await,
    }
}

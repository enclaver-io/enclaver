#![allow(clippy::new_without_default)]

pub mod api;
pub mod aux_api;
pub mod config;
pub mod console;
pub mod egress;
pub mod enclave;
pub mod helios_rpc;
pub mod ingress;
pub mod kms_proxy;
pub mod launcher;

use anyhow::Result;
use clap::Parser;
use log::{error, info};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use enclaver::constants::{APP_LOG_PORT, STATUS_PORT};
use enclaver::nsm::Nsm;

use api::ApiService;
use aux_api::AuxApiService;
use config::Configuration;
use console::{AppLog, AppStatus};
use egress::EgressService;
use helios_rpc::HeliosRpcService;
use ingress::IngressService;
use kms_proxy::KmsProxyService;

#[derive(Parser)]
struct CliArgs {
    #[clap(long = "no-bootstrap", action)]
    no_bootstrap: bool,

    #[clap(long = "no-console", action)]
    no_console: bool,

    #[clap(long = "config-dir")]
    config_dir: String,

    #[clap(long = "work-dir")]
    work_dir: Option<PathBuf>,

    #[clap(required = true)]
    entrypoint: Vec<OsString>,

    #[clap(long = "verbose", short = 'v', action = clap::ArgAction::Count)]
    verbosity: u8,
}

async fn launch(args: &CliArgs) -> Result<launcher::ExitStatus> {
    let config = Arc::new(Configuration::load(&args.config_dir).await?);

    let nsm = Arc::new(Nsm::new());

    if !args.no_bootstrap {
        enclave::bootstrap(nsm.clone()).await?;
        info!("Enclave initialized");
    }

    let egress = EgressService::start(&config).await?;

    // Start Helios in background (non-blocking, app starts immediately)
    let helios_rpc = HeliosRpcService::start(&config).await?;

    let (kms_proxy, api, aux_api) = tokio::try_join!(
        KmsProxyService::start(config.clone(), nsm.clone()),
        ApiService::start(&config, nsm.clone()),
        AuxApiService::start(&config),
    )?;

    // Start ingress last, once all local services are bound and ready
    let ingress = IngressService::start(&config)?;

    let creds = launcher::Credentials { uid: 0, gid: 0 };

    info!("Starting {:?}", args.entrypoint);
    let exit_status =
        launcher::start_child(args.entrypoint.clone(), creds, args.work_dir.clone()).await??;
    info!("Entrypoint {}", exit_status);

    aux_api.stop().await;
    api.stop().await;
    kms_proxy.stop().await;
    helios_rpc.stop().await;
    ingress.stop().await;
    egress.stop().await;

    Ok(exit_status)
}

async fn run(args: &CliArgs) -> Result<()> {
    // Start the status and logs listeners ASAP so that if we fail to
    // initialize, we can communicate the status and stream the logs
    let app_status = AppStatus::new();
    let app_status_task = app_status.start_serving(STATUS_PORT);

    let mut console_task = None;
    if !args.no_console {
        let app_log = AppLog::with_stdio_redirect()?;
        console_task = Some(app_log.start_serving(APP_LOG_PORT));
    }

    match launch(args).await {
        Ok(exit_status) => app_status.exited(exit_status),
        Err(err) => app_status.fatal(err.to_string()),
    };

    app_status_task.await??;

    if let Some(task) = console_task {
        task.abort();
        _ = task.await;
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();
    enclaver::utils::init_logging(args.verbosity);

    #[cfg(feature = "tracing")]
    console_subscriber::ConsoleLayer::builder()
        .with_default_env()
        .server_addr(([0, 0, 0, 0], 51000))
        .init();

    if let Err(err) = run(&args).await {
        error!("Error: {err:#}");
        std::process::exit(1);
    }
}

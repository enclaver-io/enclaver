use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use enclaver::{
    build::EnclaveArtifactBuilder, build::ResolvedSources, constants::MANIFEST_FILE_NAME,
    images::ImageRef, manifest::load_manifest, nitro_cli::EIFMeasurements, run_container::Sleeve,
};
use log::{debug, error};

#[derive(Debug, Parser)]
#[clap(author, version)]
/// Package and run applications in Nitro Enclaves.
struct Cli {
    #[clap(subcommand)]
    subcommand: Commands,

    #[clap(long = "verbose", short = 'v', action = clap::ArgAction::Count)]
    verbosity: u8,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[clap(name = "build")]
    /// Package a Docker image into a self-executing Enclaver container image.
    Build {
        #[clap(long = "file", short = 'f', default_value = "enclaver.yaml")]
        /// Path to the Enclaver manifest file, or - to read it from stdin.
        manifest_file: String,

        #[clap(long = "eif-only", hide = true)]
        /// Only build the EIF file, do not package it into a self-executing image.
        eif_file: Option<String>,

        #[clap(long = "pull")]
        /// Pull every container image to ensure the latest version
        force_pull: bool,
    },

    #[clap(name = "run")]
    /// Run a packaged Enclaver container image without typing long Docker commands.
    ///
    /// This command is a convenience utility that runs a pre-existing Enclaver image
    /// in the local Docker Daemon. It is equivalent to running the image with Docker,
    /// and passing:
    ///
    ///     '--device=/dev/nitro_enclaves:/dev/nitro_enclaves:rw'.
    ///
    /// Requires a local Docker Daemon to be running, and that this computer is an AWS
    /// instance configured to support Nitro Enclaves.
    Run {
        #[clap(long = "file", short = 'f')]
        /// Enclaver Manifest file in which to look for an image name.
        ///
        /// Defaults to enclaver.yaml if not set and no image is specified. To run a specific
        /// image instead, pass the name of the image as an argument.
        manifest_file: Option<String>,

        #[clap(index = 1, name = "image")]
        /// Name of a pre-existing Enclaver image to run.
        ///
        /// To automatically look this value up from an Enclaver manifest, use -f, or
        /// execute this command with an enclaver.yaml file in the current directory.
        image_name: Option<String>,

        #[clap(short = 'p', long = "publish")]
        /// Port to expose on the host machine, for example: 8080:80.
        port_forwards: Vec<String>,

        #[clap(short, long)]
        /// Run the enclave supervisor in debug mode
        debug_mode: bool,
    },
}

async fn run(args: Cli) -> Result<()> {
    match args.subcommand {
        // Build an OCI image based on a manifest file.
        Commands::Build {
            manifest_file,
            eif_file: None,
            force_pull,
        } => {
            let builder = EnclaveArtifactBuilder::new(force_pull)?;
            let (eif_info, resolved_sources, release_img) =
                builder.build_release(&manifest_file).await?;

            let build_summary = BuildSummary {
                sources: resolved_sources,
                measurements: eif_info.measurements,
                image: release_img,
            };

            serde_json::to_writer_pretty(std::io::stdout(), &build_summary)?;
            println!();

            Ok(())
        }

        // Build an EIF file based on a manifest file (useful for debugging, not meant for production use).
        Commands::Build {
            manifest_file,
            eif_file: Some(eif_file),
            force_pull,
            ..
        } => {
            let builder = EnclaveArtifactBuilder::new(force_pull)?;
            let (eif_info, eif_path) = builder.build_eif_only(&manifest_file, &eif_file).await?;

            println!("Built EIF: {}", eif_path.display());
            println!("EIF Info:");

            serde_json::to_writer_pretty(std::io::stdout(), &eif_info)?;
            println!();

            Ok(())
        }

        // Run an enclaver image.
        Commands::Run {
            manifest_file,
            image_name,
            port_forwards,
            debug_mode,
        } => {
            let image_name = match (manifest_file, image_name) {
                // If an image was specified, use it
                (None, Some(image_name)) => Ok(image_name),

                // If no image was specified, either use the specified manifest file or the default
                // to try to look up the target image name.
                (manifest_file, None) => {
                    let manifest_file =
                        manifest_file.unwrap_or_else(|| MANIFEST_FILE_NAME.to_string());
                    let manifest = load_manifest(manifest_file).await?;
                    Ok(manifest.target)
                }

                // Specifying both is an error
                (Some(_), Some(_)) => Err(anyhow!(
                    "both an image name and a manifest file were specified"
                )),
            }?;

            let mut runner = Sleeve::new()?;

            let shutdown_signal = enclaver::utils::register_shutdown_signal_handler().await?;

            tokio::select! {
                res = runner.run_enclaver_image(&image_name, port_forwards, debug_mode) => {
                    debug!("enclave exited");
                    match res {
                        Ok(_) => debug!("enclave exited successfully"),
                        Err(e) => error!("error running enclave: {e:#}"),
                    }
                }
                _ = shutdown_signal => {
                    debug!("signal received, cleaning up...");
                }
            }

            runner.cleanup().await?;

            Ok(())
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct BuildSummary {
    #[serde(rename = "Sources")]
    sources: ResolvedSources,

    #[serde(rename = "Measurements")]
    measurements: EIFMeasurements,

    #[serde(rename = "Image")]
    image: ImageRef,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    enclaver::utils::init_logging(args.verbosity);

    #[cfg(feature = "tracing")]
    console_subscriber::ConsoleLayer::builder()
        .with_default_env()
        .server_addr(([127, 0, 0, 1], 51002));

    run(args).await
}

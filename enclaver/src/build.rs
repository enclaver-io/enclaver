use crate::constants::{
    EIF_FILE_NAME, ENCLAVE_CONFIG_DIR, ENCLAVE_ODYN_PATH, MANIFEST_FILE_NAME, RELEASE_BUNDLE_DIR,
};
use crate::images::{FileBuilder, FileSource, ImageManager, ImageRef, LayerBuilder};
use crate::manifest::{load_manifest, Manifest};
use crate::nitro_cli::{EIFInfo, KnownIssue};
use crate::nitro_cli_container::NitroCLIContainer;
pub use crate::nitro_cli_container::SigningInfo;
use anyhow::{anyhow, bail, Result};
use bollard::models::{ImageConfig};
use bollard::query_parameters::{
    RemoveImageOptions,
};
use bollard::Docker;
use futures_util::stream::{StreamExt};
use log::{debug, info, warn};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::fs::{canonicalize, rename};
use uuid::Uuid;
const ENCLAVE_OVERLAY_CHOWN: &str = "0:0";
const RELEASE_OVERLAY_CHOWN: &str = "0:0";

const NITRO_CLI_IMAGE: &str = "public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest";
const ODYN_IMAGE: &str = "public.ecr.aws/s2t1d4c6/enclaver-io/odyn:latest";
const ODYN_IMAGE_BINARY_PATH: &str = "/usr/local/bin/odyn";
const SLEEVE_IMAGE: &str = "public.ecr.aws/s2t1d4c6/enclaver-io/enclaver-wrapper-base:latest";

pub struct EnclaveArtifactBuilder {
    docker: Arc<Docker>,
    image_manager: ImageManager,
    pull_tags: bool,
}

impl EnclaveArtifactBuilder {
    pub fn new(pull_tags: bool) -> Result<Self> {
        let docker_client = Arc::new(
            Docker::connect_with_local_defaults()
                .map_err(|e| anyhow!("connecting to docker: {}", e))?,
        );

        Ok(Self {
            pull_tags,
            docker: docker_client.clone(),
            image_manager: ImageManager::new_with_docker(docker_client)?,
        })
    }

    /// Build a release image based on the referenced manifest.
    pub async fn build_release(&self, manifest_path: &str) -> Result<(EIFInfo, ResolvedSources, ImageRef)> {
        let ibr = self.common_build(manifest_path).await?;
        let eif_path = ibr.build_dir.path().join(EIF_FILE_NAME);
        let mut release_img = self
            .package_eif(eif_path, manifest_path, &ibr.resolved_sources)
            .await?;

        let release_tag = &ibr.manifest.target;
        release_img.name = Some(release_tag.to_string());

        self.image_manager
            .tag_image(&release_img, release_tag)
            .await?;

        Ok((ibr.eif_info, ibr.resolved_sources, release_img))
    }

    /// Build an EIF, as would be included in a release image, based on the referenced manifest.
    pub async fn build_eif_only(
        &self,
        manifest_path: &str,
        dst_path: &str,
    ) -> Result<(EIFInfo, PathBuf)> {
        let ibr = self.common_build(manifest_path).await?;
        let eif_path = ibr.build_dir.path().join(EIF_FILE_NAME);
        rename(&eif_path, dst_path).await?;

        Ok((ibr.eif_info, canonicalize(dst_path).await?))
    }

    /// Load the referenced manifest, amend the image it references to match what we expect in
    /// an enclave, then convert the resulting image to an EIF.
    async fn common_build(&self, manifest_path: &str) -> Result<IntermediateBuildResult> {
        let manifest = load_manifest(manifest_path).await?;

        self.analyze_manifest(&manifest);

        let resolved_sources = self.resolve_sources(&manifest).await?;

        let amended_img = self
            .amend_source_image(&resolved_sources, manifest_path)
            .await?;

        info!("built intermediate image: {}", amended_img);

        let build_dir = TempDir::new()?;

        let sign: Option<SigningInfo> = if let Some(signature) = &manifest.signature {
            if let Some(parent_path) = PathBuf::from(manifest_path).parent() {
                Some(SigningInfo {
                    certificate: canonicalize(parent_path.join(&signature.certificate)).await?,
                    key: canonicalize(parent_path.join(&signature.key)).await?,
                })
            } else {
                bail!("Failed to get parent path of manifest");
            }
        } else {
            None
        };

        let eif_info = self
            .image_to_eif(
                &amended_img,
                resolved_sources.nitro_cli.clone(),
                &build_dir,
                EIF_FILE_NAME,
                sign,
            )
            .await?;

        Ok(IntermediateBuildResult {
            manifest,
            resolved_sources,
            build_dir,
            eif_info,
        })
    }

    /// Amend a source image by adding one or more layers containing the files we expect
    /// to have within the enclave.
    async fn amend_source_image(
        &self,
        sources: &ResolvedSources,
        manifest_path: &str,
    ) -> Result<ImageRef> {
        let img_config = self
            .docker
            .inspect_image(sources.app.to_str())
            .await?
            .config;

        // Find the CMD and ENTRYPOINT from the source image. If either was specified in "shell form"
        // Docker seems to convert it to "exec form" as an actual shell invocation, so we can simply
        // ignore that possibility.
        //
        // Since the enclave image cannot take any arguments (which would normally override a CMD),
        // we can simply take everything from CMD and append it to the ENTRYPOINT, then append that
        // whole thing to the odyn invocation.
        // TODO(russell_h): Figure out what happens when a source image specifies env variables.
        let mut cmd = match img_config {
            Some(ImageConfig {
                cmd: Some(ref cmd), ..
            }) => cmd.clone(),
            _ => vec![],
        };

        let mut entrypoint = match img_config {
            Some(ImageConfig {
                entrypoint: Some(ref entrypoint),
                ..
            }) => entrypoint.clone(),
            _ => vec![],
        };

        let mut odyn_command = vec![
            String::from(ENCLAVE_ODYN_PATH),
            String::from("--config-dir"),
            String::from("/etc/enclaver"),
            String::from("--"),
        ];

        odyn_command.append(&mut entrypoint);
        odyn_command.append(&mut cmd);

        debug!("appending layer to source image");
        let amended_image = self
            .image_manager
            .append_layer(
                &sources.app,
                LayerBuilder::new()
                    .append_file(FileBuilder {
                        path: PathBuf::from(ENCLAVE_CONFIG_DIR).join(MANIFEST_FILE_NAME),
                        source: FileSource::Local {
                            path: PathBuf::from(manifest_path),
                        },
                        chown: ENCLAVE_OVERLAY_CHOWN.to_string(),
                    })
                    .append_file(FileBuilder {
                        path: PathBuf::from(ENCLAVE_ODYN_PATH),
                        source: FileSource::Image {
                            name: sources.odyn.to_string(),
                            path: ODYN_IMAGE_BINARY_PATH.into(),
                        },
                        chown: ENCLAVE_OVERLAY_CHOWN.to_string(),
                    })
                    .set_entrypoint(odyn_command),
            )
            .await?;

        Ok(amended_image)
    }

    /// Convert an EIF file into a release OCI image.
    ///
    /// TODO: this currently is incomplete; file permissions are wrong, the base image
    /// doesn't match our current requirements, and the exact intended format is still
    /// TBD.
    async fn package_eif(
        &self,
        eif_path: PathBuf,
        manifest_path: &str,
        sources: &ResolvedSources,
    ) -> Result<ImageRef> {
        info!("packaging EIF into release image");
        debug!("EIF file: {}", eif_path.to_string_lossy());

        let packaged_img = self
            .image_manager
            .append_layer(
                &sources.sleeve,
                LayerBuilder::new()
                    .append_file(FileBuilder {
                        path: PathBuf::from(RELEASE_BUNDLE_DIR).join(MANIFEST_FILE_NAME),
                        source: FileSource::Local {
                            path: PathBuf::from(manifest_path),
                        },
                        chown: RELEASE_OVERLAY_CHOWN.to_string(),
                    })
                    .append_file(FileBuilder {
                        path: PathBuf::from(RELEASE_BUNDLE_DIR).join(EIF_FILE_NAME),
                        source: FileSource::Local { path: eif_path },
                        chown: RELEASE_OVERLAY_CHOWN.to_string(),
                    }),
            )
            .await?;

        Ok(packaged_img)
    }

    /// Convert the referenced image to an EIF file, which will be deposited into `build_dir`
    /// using the file name `eif_name`.
    ///
    /// This operates by mounting the build dir into a docker container, and invoking `nitro-cli build-enclave`
    /// inside that container.
    async fn image_to_eif(
        &self,
        source_img: &ImageRef,
        nitro_cli_img: ImageRef,
        build_dir: &TempDir,
        eif_name: &str,
        sign: Option<SigningInfo>,
    ) -> Result<EIFInfo> {
        let build_dir_path = build_dir.path().to_str().unwrap();

        // There is currently no way to point nitro-cli to a local image ID; it insists
        // on attempting to pull the image (this may be a bug;. As a workaround, give our image a random
        // tag, and pass that.
        let img_tag = Uuid::new_v4().to_string();
        self.image_manager.tag_image(source_img, &img_tag).await?;

        debug!("tagged intermediate image: {}", img_tag);

        let nitro_cli = NitroCLIContainer::new(self.docker.clone(), nitro_cli_img);
        let build_container_id = nitro_cli.build_enclave(eif_name, &img_tag, build_dir_path, sign).await?;

        info!(
            "started nitro-cli build-eif in container: {}",
            build_container_id
        );

        // Convert docker output to log lines, to give the user some feedback as to what is going on.
        let mut detected_nitro_cli_issue = None;

        let mut stderr_stream = nitro_cli.stderr(&build_container_id, true);
        while let Some(line) = stderr_stream.next().await {
            // Note that these come with trailing newlines, which we trim off.
            let trimmed = line.trim_end();

            if detected_nitro_cli_issue.is_none() {
                detected_nitro_cli_issue = KnownIssue::detect(&line);
            }

            info!(target: "nitro-cli::build-eif", "{trimmed}");
        }

        if let Some(issue) = detected_nitro_cli_issue {
            warn!(
                "detected known nitro-cli issue:\n{}",
                issue.helpful_message()
            );
        }

        let status_code = nitro_cli.wait_container(&build_container_id).await?;
        if status_code != 0 {
            bail!("non-zero exit code from nitro-cli");
        }

        let mut json_buf = Vec::with_capacity(4096);
        let mut stdout_stream = nitro_cli.stdout(&build_container_id, false);

        while let Some(line) = stdout_stream.next().await {
            json_buf.extend_from_slice(line.as_ref());
        }

        // If we make it this far, do a little bit of cleanup
        nitro_cli.remove_container(&build_container_id).await?;
        let _ = self
            .docker
            .remove_image(&img_tag, None::<RemoveImageOptions>, None)
            .await?;

        Ok(serde_json::from_slice(&json_buf)?)
    }

    fn analyze_manifest(&self, manifest: &Manifest) {
        if manifest.ingress.is_none() {
            info!(
                "no ingress specified in manifest; there will be no way to connect to this enclave"
            );
        }

        if manifest.egress.is_none() {
            info!("no egress specified in manifest; this enclave will have no outbound network access");
        }
    }

    // External images are images whose tags we do not normally manage. In other words,
    // a user tags an image, then gives us that tag - and unless specifically instructed
    // otherwise we should not overwrite that tag.
    async fn resolve_external_source_image(&self, image_name: &str) -> Result<ImageRef> {
        if self.pull_tags {
            self.image_manager.pull_image(image_name).await
        } else {
            self.image_manager.find_or_pull(image_name).await
        }
    }

    async fn resolve_internal_source_image(
        &self,
        name_override: Option<&str>,
        default: &str,
    ) -> Result<ImageRef> {
        match name_override {
            Some(image_name) => {
                let mut img = self.image_manager.find_or_pull(image_name).await?;
                img.name = Some(image_name.to_string());
                Ok(img)
            }
            None => {
                let mut img = self.image_manager.pull_image(default).await?;
                img.name = Some(default.to_string());
                Ok(img)
            }
        }
    }

    async fn resolve_sources(&self, manifest: &Manifest) -> Result<ResolvedSources> {
        let app = self
            .resolve_external_source_image(&manifest.sources.app)
            .await?;
        info!("using app image: {app}");

        let odyn = self
            .resolve_internal_source_image(manifest.sources.odyn.as_deref(), ODYN_IMAGE)
            .await?;
        if manifest.sources.odyn.is_none() {
            debug!("no supervisor image specified in manifest; using default: {odyn}");
        } else {
            info!("using supervisor image: {odyn}");
        }

        let release_base = self
            .resolve_internal_source_image(manifest.sources.sleeve.as_deref(), SLEEVE_IMAGE)
            .await?;
        if manifest.sources.sleeve.is_none() {
            debug!("no sleeve base image specified in manifest; using default: {release_base}");
        } else {
            info!("using sleeve base image: {release_base}");
        }

        let nitro_cli = self
            .resolve_internal_source_image(None, NITRO_CLI_IMAGE)
            .await?;
        info!("using nitro-cli image: {nitro_cli}");

        let sources = ResolvedSources {
            app,
            odyn,
            nitro_cli,
            sleeve: release_base,
        };

        Ok(sources)
    }
}

struct IntermediateBuildResult {
    manifest: Manifest,
    resolved_sources: ResolvedSources,
    build_dir: TempDir,
    eif_info: EIFInfo,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResolvedSources {
    #[serde(rename = "App")]
    app: ImageRef,

    #[serde(rename = "Odyn")]
    odyn: ImageRef,

    #[serde(rename = "NitroCLI")]
    nitro_cli: ImageRef,

    #[serde(rename = "Sleeve")]
    sleeve: ImageRef,
}

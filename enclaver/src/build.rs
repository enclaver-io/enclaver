use crate::constants::{
    EIF_FILE_NAME, ENCLAVE_CONFIG_DIR, ENCLAVE_ODYN_PATH, MANIFEST_FILE_NAME, RELEASE_BUNDLE_DIR,
};
use crate::images::{FileBuilder, FileSource, ImageManager, ImageRef, LayerBuilder};
use crate::manifest::{load_manifest, Manifest};
use crate::nitro_cli::{EIFInfo, KnownIssue};
use anyhow::{anyhow, Result};
use bollard::container::{Config, LogOutput, LogsOptions, WaitContainerOptions};
use bollard::models::{ImageConfig, HostConfig, Mount, MountTypeEnum};
use bollard::Docker;
use futures_util::stream::{StreamExt, TryStreamExt};
use log::{debug, info, warn};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::fs::{canonicalize, rename};
use uuid::Uuid;

const ENCLAVE_OVERLAY_CHOWN: &str = "0:0";
const RELEASE_OVERLAY_CHOWN: &str = "0:0";

const NITRO_CLI_IMAGE: &str = "public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest";
const ODYN_IMAGE: &str = "public.ecr.aws/s2t1d4c6/enclaver-io/odyn";
const ODYN_IMAGE_BINARY_PATH: &str = "/usr/local/bin/odyn";
const RELEASE_BASE_IMAGE: &str = "public.ecr.aws/s2t1d4c6/enclaver-io/enclaver-wrapper-base";

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
    pub async fn build_release(&self, manifest_path: &str) -> Result<(EIFInfo, ImageRef, String)> {
        let ibr = self.common_build(manifest_path).await?;
        let eif_path = ibr.build_dir.path().join(EIF_FILE_NAME);
        let release_img = self
            .package_eif(eif_path, manifest_path, &ibr.resolved_sources)
            .await?;

        let release_tag = &ibr.manifest.target;

        self.image_manager
            .tag_image(&release_img, release_tag)
            .await?;

        Ok((ibr.eif_info, release_img, release_tag.to_string()))
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

        let mut certificate_path: Option<PathBuf> = None;
        let mut key_path: Option<PathBuf> = None;

        if let Some(signature) = &manifest.signature {
            if let Some(parent_path) = PathBuf::from(manifest_path).parent() {
                certificate_path = Some(canonicalize(parent_path.join(&signature.certificate)).await?);
                key_path = Some(canonicalize(parent_path.join(&signature.key)).await?);
            } else {
                return Err(anyhow!("Failed to get parent path of manifest"));
            }
        }

        let eif_info = self
            .image_to_eif(&amended_img, &build_dir, EIF_FILE_NAME, key_path, certificate_path)
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
                &sources.release_base,
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
        build_dir: &TempDir,
        eif_name: &str,
        key: Option<PathBuf>,
        certificate: Option<PathBuf>
    ) -> Result<EIFInfo> {
        let build_dir_path = build_dir.path().to_str().unwrap();

        // There is currently no way to point nitro-cli to a local image ID; it insists
        // on attempting to pull the image (this may be a bug;. As a workaround, give our image a random
        // tag, and pass that.
        let img_tag = Uuid::new_v4().to_string();
        self.image_manager.tag_image(source_img, &img_tag).await?;

        debug!("tagged intermediate image: {}", img_tag);

        // Note: we're deliberately not modeling nitro-cli as part of ResolvedSources.
        // I might be overthinking this, but it doesn't directly end up as part of the
        // final artifact, and it is very likely that two different versions of nitro-cli
        // would output an identical EIF, so this seems like it should be modeled as more
        // of a toolchain than a source. In any case there isn't much use-case for overriding
        // it right now (perhaps pinning though), so deferring that problem for later.
        let nitro_cli = self.resolve_external_source_image(NITRO_CLI_IMAGE).await?;

        debug!("using nitro-cli image: {nitro_cli}");

        let mut cmd = vec![
            "build-enclave",
            "--docker-uri",
            &img_tag,
            "--output-file",
            eif_name,
        ];

        let mut mounts = vec![
            Mount {
                typ: Some(MountTypeEnum::BIND),
                source: Some(String::from("/var/run/docker.sock")),
                target: Some(String::from("/var/run/docker.sock")),
                ..Default::default()
            },
            Mount {
                typ: Some(MountTypeEnum::BIND),
                source: Some(build_dir_path.into()),
                target: Some(String::from("/build")),
                ..Default::default()
            },
        ];

        if let (Some(key_path), Some(certificate_path)) = (key, certificate) {
            cmd.push("--signing-certificate");
            cmd.push("/var/run/certificate");
            cmd.push("--private-key");
            cmd.push("/var/run/key");


            mounts.push(Mount {
                typ: Some(MountTypeEnum::BIND),
                source: Some(key_path.to_string_lossy().to_string()),
                target: Some(String::from("/var/run/key")),
                ..Default::default()
            });

            mounts.push(Mount {
                typ: Some(MountTypeEnum::BIND),
                source: Some(certificate_path.to_string_lossy().to_string()),
                target: Some(String::from("/var/run/certificate")),
                ..Default::default()
            });
        }

        let build_container_id = self
            .docker
            .create_container::<&str, &str>(
                None,
                Config {
                    image: Some(nitro_cli.to_str()),
                    cmd: Some(cmd),
                    attach_stderr: Some(true),
                    attach_stdout: Some(true),
                    host_config: Some(HostConfig {
                        mounts: Some(mounts),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?
            .id;

        info!(
            "starting nitro-cli build-eif in container: {}",
            build_container_id
        );

        self.docker
            .start_container::<String>(&build_container_id, None)
            .await?;

        // Convert docker output to log lines, to give the user some feedback as to what is going on.
        let mut log_stream = self.docker.logs::<String>(
            &build_container_id,
            Some(LogsOptions {
                follow: true,
                stderr: true,
                ..Default::default()
            }),
        );

        let mut detected_nitro_cli_issue = None;

        while let Some(Ok(LogOutput::StdErr { message: bytes })) = log_stream.next().await {
            // Note that these come with trailing newlines, which we trim off.
            let line = String::from_utf8_lossy(&bytes);
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

        let status_code = self
            .docker
            .wait_container(&build_container_id, None::<WaitContainerOptions<String>>)
            .try_collect::<Vec<_>>()
            .await?
            .first()
            .ok_or_else(|| anyhow!("missing wait response from daemon",))?
            .status_code;

        if status_code != 0 {
            return Err(anyhow!("non-zero exit code from nitro-cli",));
        }

        let mut json_buf = Vec::with_capacity(4096);
        let mut log_stream = self.docker.logs::<String>(
            &build_container_id,
            Some(LogsOptions {
                stdout: true,
                ..Default::default()
            }),
        );

        while let Some(Ok(LogOutput::StdOut { message })) = log_stream.next().await {
            json_buf.extend_from_slice(message.as_ref());
        }

        // If we make it this far, do a little bit of cleanup
        self.docker
            .remove_container(&build_container_id, None)
            .await?;
        let _ = self.docker.remove_image(&img_tag, None, None).await?;

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
            Some(image_name) => self.image_manager.find_or_pull(image_name).await,
            None => self.image_manager.pull_image(default).await,
        }
    }

    async fn resolve_sources(&self, manifest: &Manifest) -> Result<ResolvedSources> {
        let app = self
            .resolve_external_source_image(&manifest.sources.app)
            .await?;
        info!("using app image: {app}");

        let odyn = self
            .resolve_internal_source_image(manifest.sources.supervisor.as_deref(), ODYN_IMAGE)
            .await?;
        if manifest.sources.supervisor.is_none() {
            debug!("no supervisor image specified in manifest; using default: {odyn}");
        } else {
            info!("using supervisor image: {odyn}");
        }

        let release_base = self
            .resolve_internal_source_image(manifest.sources.wrapper.as_deref(), RELEASE_BASE_IMAGE)
            .await?;
        if manifest.sources.wrapper.is_none() {
            debug!("no wrapper base image specified in manifest; using default: {release_base}");
        } else {
            info!("using wrapper base image: {release_base}");
        }

        let sources = ResolvedSources {
            app,
            odyn,
            release_base,
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

struct ResolvedSources {
    app: ImageRef,
    odyn: ImageRef,
    release_base: ImageRef,
}

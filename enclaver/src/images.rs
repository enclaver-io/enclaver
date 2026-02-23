use crate::utils::StringablePathExt;
use anyhow::{Context, Result, anyhow};
use bollard::Docker;
use bollard::models::{BuildInfo, CreateImageInfo, ImageId};
use bollard::query_parameters::{BuildImageOptions, CreateImageOptions, TagImageOptions};
use futures_util::stream::{StreamExt, TryStreamExt};
use log::{debug, trace};
use std::fmt;
use std::fmt::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::{File, create_dir};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter, duplex};
use tokio_util::codec;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageRef {
    #[serde(rename = "ID")]
    pub id: String,

    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(rename = "RepoDigest", skip_serializing_if = "Option::is_none")]
    pub repo_digest: Option<String>,
}

impl ImageRef {
    pub fn to_str(&self) -> &str {
        &self.id
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// An interface for manipulating Docker images.
pub struct ImageManager {
    docker: Arc<Docker>,
}

impl ImageManager {
    /// Constructs a new ImageManager pointing to a local Docker daemon.
    #[allow(dead_code)]
    pub fn new() -> Result<Self> {
        let docker_client = Arc::new(
            Docker::connect_with_local_defaults()
                .map_err(|e| anyhow!("connecting to docker: {}", e))?,
        );

        Ok(Self {
            docker: docker_client,
        })
    }

    /// Constructs a new ImageManager pointing to a local Docker daemon.
    pub fn new_with_docker(docker: Arc<Docker>) -> Result<Self> {
        Ok(Self { docker })
    }

    /// Resolves a name-like string to an ImageRef referencing a specific immutable image.
    pub async fn image(&self, name: &str) -> Result<ImageRef> {
        debug!("attempting to resolve image: {name}");
        let img = self
            .docker
            .inspect_image(name)
            .await
            .with_context(|| format!("inspecting image {}", name))?;

        match img.id {
            Some(id) => Ok(ImageRef {
                id,
                name: None,
                repo_digest: img.repo_digests.unwrap_or_default().first().cloned(),
            }),
            None => Err(anyhow!("missing image ID in image_inspect result")),
        }
    }

    /// Look for a local image with the specified name. If it exists, return it. Otherwise, attempt
    /// to pull the specified name from a remote registry.
    pub async fn find_or_pull(&self, image_name: &str) -> Result<ImageRef> {
        debug!("looking for image {image_name}");
        let img = match self.image(image_name).await {
            Ok(img) => Ok(Some(img)),
            Err(e) => match e.downcast_ref::<bollard::errors::Error>() {
                Some(bollard::errors::Error::DockerResponseServerError {
                    status_code: 404,
                    ..
                }) => Ok(None),
                _ => Err(e),
            },
        }?;

        match img {
            Some(img) => {
                debug!("found local image {image_name}");
                Ok(img)
            }
            None => {
                debug!("local image not found, attempting to pull {image_name}");
                self.pull_image(image_name).await
            }
        }
    }

    /// Pull an image from a remote registry, if it is not already present, while streaming
    /// output to the terminal.
    pub async fn pull_image(&self, image_name: &str) -> Result<ImageRef> {
        debug!("fetching image: {}", image_name);
        let mut fetch_stream = self.docker.create_image(
            Some(CreateImageOptions {
                from_image: Some(image_name.to_string()),
                ..Default::default()
            }),
            None,
            None,
        );

        while let Some(item) = fetch_stream.next().await {
            let create_image_info = item?;
            if let CreateImageInfo {
                id: Some(id),
                status: Some(status),
                ..
            } = create_image_info
            {
                debug!("{}: {}", id, status);
            }
        }

        self.image(image_name).await
    }

    /// Build and append a new layer to an image.
    ///
    /// This works by converting `layer` to a docker build operation, and executing
    /// that operation against the connected docker daemon.
    pub async fn append_layer(&self, img: &ImageRef, layer: &LayerBuilder) -> Result<ImageRef> {
        // We're going to realize `layer` to a docker context, in the form of a tarball.
        // Rather than realizing the full tarball into memory, we'll construct a pipe-like
        // pair of streams, and lazily write the tarball to one of them while streaming
        // the other end of the pipe into the daemon request.
        let (tar_write, tar_read) = duplex(1024);
        let byte_stream =
            codec::FramedRead::new(tar_read, codec::BytesCodec::new()).map(|r| r.unwrap().freeze());

        // Concurrently build the context tarball and perform the build request.
        let (realize_res, build_res) = tokio::join!(
            layer.realize(&img.id, tar_write),
            self.docker
                .build_image(
                    BuildImageOptions {
                        dockerfile: "Dockerfile".to_string(),
                        rm: true,
                        ..Default::default()
                    },
                    None,
                    Some(bollard::body_stream(byte_stream)),
                )
                .try_collect::<Vec<_>>(),
        );

        realize_res?;

        // The build process streams back a bunch of BuildInfos. One of them
        // should contain the ID of the resulting image; hunt through them and
        // find it.
        let build_infos = build_res?;
        let mut maybe_id = None;

        for info in &build_infos {
            match info {
                BuildInfo {
                    aux: Some(ImageId { id: Some(id) }),
                    ..
                } => {
                    maybe_id = Some(id);
                    break;
                }
                BuildInfo {
                    error: Some(msg), ..
                } => return Err(anyhow!("build error appending layer: {}", msg)),
                _ => {}
            }
        }

        match maybe_id {
            Some(image_id) => self.image(image_id).await,
            None => Err(anyhow!("missing image ID",)),
        }
    }

    /// Tag an image.
    pub async fn tag_image(&self, img: &ImageRef, tag: &str) -> Result<()> {
        self.docker
            .tag_image(
                img.to_str(),
                Some(TagImageOptions {
                    repo: Some(tag.to_string()),
                    ..Default::default()
                }),
            )
            .await?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum FileSource {
    Local {
        path: PathBuf,
    },

    #[allow(dead_code)]
    Image {
        name: String,
        path: PathBuf,
    },
}

#[derive(Debug)]
pub struct FileBuilder {
    pub path: PathBuf,
    pub source: FileSource,
    pub chown: String,
}

impl FileBuilder {
    fn realize(&self) -> Result<String> {
        let mut line = String::from("COPY");
        let local_path = self.path.must_to_str()?;

        let dst_path = self.path.must_to_str()?;

        write!(&mut line, " --chown={}", self.chown)?;

        match &self.source {
            FileSource::Local { .. } => {
                write!(&mut line, " files/{}", local_path)?;
            }
            FileSource::Image {
                name: image_name,
                path,
            } => {
                let src_path = path.must_to_str()?;
                write!(&mut line, " --from={} {}", image_name, src_path)?;
            }
        }

        writeln!(&mut line, " {}", dst_path)?;

        Ok(line)
    }
}

pub struct LayerBuilder {
    files: Vec<FileBuilder>,

    entrypoint: Option<Vec<String>>,
}

impl LayerBuilder {
    pub fn new() -> Self {
        Self {
            files: vec![],
            entrypoint: None,
        }
    }

    /// Add a file to the LayerBuilder, in the form of a FileBuilder.
    pub fn append_file(&mut self, file: FileBuilder) -> &mut Self {
        self.files.push(file);
        self
    }

    /// Set the entrypoint for the layer.
    pub fn set_entrypoint(&mut self, entrypoint: Vec<String>) -> &mut Self {
        self.entrypoint = Some(entrypoint);
        self
    }

    /// Realize the LayerBuilder to a tarred up Docker context containing a Dockerfile
    /// which will build the requested layer, and write the resulting context to `dst`.
    ///
    /// Note that currently this builds the context on the filesystem before generating
    /// a tarball from that file tree, but in the future it could build the context directly
    /// into the tar stream.
    async fn realize<W: AsyncWrite + Unpin + Send + 'static>(
        &self,
        source_image_name: &str,
        dst: W,
    ) -> Result<()> {
        // Create a temporary directory in which to construct a Docker context.
        let tempdir = tempfile::TempDir::new()?;
        trace!(
            "realizing Docker build env to temp directory: {}",
            tempdir.path().to_string_lossy()
        );

        // Create a "files" subdirectory. Within "files" we will hardlink any
        // local files to be copied to the image.
        let local_files = tempdir.path().join("files");
        create_dir(&local_files).await?;

        // We'll also write out a Dockerfile with a COPY line for each file:
        // - for local files we'll COPY from the "files" directory
        // - for image-sourced files we'll write COPY to pull from the image
        let mut dw = BufWriter::new(File::create(tempdir.path().join("Dockerfile")).await?);

        dw.write_all(format!("FROM {source_image_name}\n\n").as_bytes())
            .await?;

        for file in &self.files {
            // For local files, hard link them into the `files` directory
            // in our context directory.
            trace!("realizing file: {:#?}", file);
            if let FileSource::Local { path: source_path } = &file.source {
                let target = local_files.join(file.path.strip_prefix("/")?);
                let target_parent = target.parent().ok_or_else(|| {
                    anyhow!("error getting parent of {}", target.to_string_lossy())
                })?;
                tokio::fs::create_dir_all(target_parent).await?;
                tokio::fs::copy(source_path, target).await?;
            }

            dw.write_all(file.realize()?.as_bytes()).await?;
        }

        // Write out the ENTRYPOINT, if set
        if let Some(entrypoint) = &self.entrypoint {
            let ep_array_str = serde_json::to_string(entrypoint)?;
            trace!("writing ENTRYPOINT: {}", ep_array_str);
            dw.write_all(format!("ENTRYPOINT {}\n", ep_array_str).as_bytes())
                .await?;
        }

        dw.flush().await?;

        // Write the entire context directory to a tarball.
        let mut tb = tokio_tar::Builder::new(dst);
        tb.append_dir_all(".", tempdir).await?;

        Ok(())
    }
}

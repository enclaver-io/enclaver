use std::sync::Arc;
use std::path::PathBuf;
use anyhow::{anyhow, Result};
use bollard::{Docker, models::{Mount, MountTypeEnum}};
use bollard::container::LogOutput;
use bollard::query_parameters::{LogsOptions, CreateContainerOptions, StartContainerOptions, WaitContainerOptions, RemoveContainerOptions};
use bollard::models::{ContainerCreateBody, HostConfig};
use futures::{future, Stream, TryStreamExt};
use crate::images::ImageRef;
use log::debug;

pub struct SigningInfo {
    pub key: PathBuf,
    pub certificate: PathBuf,
}

pub struct NitroCLIContainer {
    docker: Arc<Docker>,
    image: ImageRef,
}

impl NitroCLIContainer {
    pub fn new(docker: Arc<Docker>, image: ImageRef) -> Self {
        Self { docker, image }
    }

    pub async fn build_enclave(&self, eif_name: &str, img_tag: &str, build_dir_path: &str, sign: Option<SigningInfo>) -> Result<String> {
        debug!("using nitro-cli image: {}", self.image.to_str());

        let mut cmd = vec![
            "build-enclave",
            "--docker-uri",
            img_tag,
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

        if let Some(sign) = sign {
            cmd.push("--signing-certificate");
            cmd.push("/var/run/certificate");
            cmd.push("--private-key");
            cmd.push("/var/run/key");

            mounts.push(Mount {
                typ: Some(MountTypeEnum::BIND),
                source: Some(sign.key.to_string_lossy().to_string()),
                target: Some(String::from("/var/run/key")),
                ..Default::default()
            });

            mounts.push(Mount {
                typ: Some(MountTypeEnum::BIND),
                source: Some(sign.certificate.to_string_lossy().to_string()),
                target: Some(String::from("/var/run/certificate")),
                ..Default::default()
            });
        }

        let container_id = self
            .docker
            .create_container(
                None::<CreateContainerOptions>,
                ContainerCreateBody {
                    image: Some(self.image.to_string()),
                    cmd: Some(cmd.iter().map(|s| s.to_string()).collect()),
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

        self.docker
            .start_container(&container_id, None::<StartContainerOptions>)
            .await?;

        Ok(container_id)
    }

    pub fn stderr(&self, container_id: &str, follow: bool) -> impl Stream<Item = String> {
        use futures::StreamExt;

        // Convert docker output to log lines, to give the user some feedback as to what is going on.
        let log_stream = self.docker.logs(
            container_id,
            Some(LogsOptions {
                follow,
                stderr: true,
                ..Default::default()
            }),
        );

        log_stream.filter_map(|out| match out {
            Ok(LogOutput::StdErr { message }) => {
                future::ready(Some(String::from_utf8_lossy(&message).to_string()))
            }
            _ => future::ready(None),
        })
    }

    pub fn stdout(&self, container_id: &str, follow: bool) -> impl Stream<Item = String> {
        use futures::StreamExt;

        // Convert docker output to log lines, to give the user some feedback as to what is going on.
        let log_stream = self.docker.logs(
            container_id,
            Some(LogsOptions {
                follow,
                stdout: true,
                ..Default::default()
            }),
        );

        log_stream.filter_map(|out| match out {
            Ok(LogOutput::StdOut { message }) => {
                future::ready(Some(String::from_utf8_lossy(&message).to_string()))
            }
            _ => future::ready(None),
        })
    }

    pub async fn wait_container(&self, container_id: &str) -> Result<i64> {
        let status_code = self
            .docker
            .wait_container(container_id, None::<WaitContainerOptions>)
            .try_collect::<Vec<_>>()
            .await?
            .first()
            .ok_or_else(|| anyhow!("missing wait response from daemon",))?
            .status_code;

        Ok(status_code)
    }

    pub async fn remove_container(&self, container_id: &str) -> Result<()> {
        self.docker.remove_container(container_id, None::<RemoveContainerOptions>).await?;
        Ok(())
    }
}
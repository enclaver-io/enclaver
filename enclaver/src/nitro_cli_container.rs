use crate::images::ImageRef;
use anyhow::{Result, anyhow};
use bollard::container::LogOutput;
use bollard::models::{ContainerCreateBody, HostConfig};
use bollard::query_parameters::{
    CreateContainerOptions, LogsOptions, RemoveContainerOptions, StartContainerOptions,
    WaitContainerOptions,
};
use bollard::{
    Docker,
    models::{Mount, MountType},
};
use futures::{Stream, TryStreamExt, future};
use log::debug;
use regex::Regex;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

static KMS_KEY_ARN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^arn:aws(?:[\-a-z]+)?:kms:[a-z0-9-]+:\d{12}:key[:/][a-zA-Z0-9-]+$")
        .expect("KMS key ARN regex must be valid")
});

const AWS_CREDENTIAL_ENV_VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
];

pub enum SigningKey {
    File(PathBuf),
    Kms(String),
}

impl SigningKey {
    pub fn is_kms_key_arn(key: &str) -> bool {
        KMS_KEY_ARN_REGEX.is_match(key)
    }
}

pub struct SigningInfo {
    pub key: SigningKey,
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

    pub async fn build_enclave(
        &self,
        eif_name: &str,
        img_tag: &str,
        build_dir_path: &str,
        sign: Option<SigningInfo>,
    ) -> Result<String> {
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
                typ: Some(MountType::BIND),
                source: Some(String::from("/var/run/docker.sock")),
                target: Some(String::from("/var/run/docker.sock")),
                ..Default::default()
            },
            Mount {
                typ: Some(MountType::BIND),
                source: Some(build_dir_path.into()),
                target: Some(String::from("/build")),
                ..Default::default()
            },
        ];

        let mut env = Vec::new();

        if let Some(sign) = &sign {
            cmd.push("--signing-certificate");
            cmd.push("/var/run/certificate");
            cmd.push("--private-key");

            match &sign.key {
                SigningKey::File(path) => {
                    cmd.push("/var/run/key");

                    mounts.push(Mount {
                        typ: Some(MountType::BIND),
                        source: Some(path.to_string_lossy().to_string()),
                        target: Some(String::from("/var/run/key")),
                        ..Default::default()
                    });
                }
                SigningKey::Kms(arn) => {
                    cmd.push(arn);

                    env.extend(AWS_CREDENTIAL_ENV_VARS.iter().filter_map(|name| {
                        std::env::var(name)
                            .ok()
                            .map(|value| format!("{name}={value}"))
                    }));
                }
            }

            mounts.push(Mount {
                typ: Some(MountType::BIND),
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
                    env: (!env.is_empty()).then_some(env),
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
        self.docker
            .remove_container(container_id, None::<RemoveContainerOptions>)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_kms_key_arn() {
        assert!(SigningKey::is_kms_key_arn(
            "arn:aws:kms:eu-central-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
        ));
        assert!(SigningKey::is_kms_key_arn(
            "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
        ));
        assert!(!SigningKey::is_kms_key_arn(
            "arn:aws:kms:eu-central-1:123456789012:alias/eif-signing"
        ));
        assert!(!SigningKey::is_kms_key_arn("keys/signing-key.pem"));
        assert!(!SigningKey::is_kms_key_arn("/etc/enclaver/arn:aws:kms"));
    }
}

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::{ChildStdout, Command};

pub struct NitroCLI {
    program: String,
}

impl NitroCLI {
    pub fn new() -> Self {
        Self {
            program: String::from("nitro-cli"),
        }
    }

    pub async fn run_and_deserialize_output<T>(&self, args: impl NitroCLIArgs) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let cmd_args = args.to_args()?;

        debug!("executing nitro-cli with args: {:#?}", cmd_args);

        let child = Command::new(&self.program)
            .args(cmd_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| anyhow!("failed to execute nitro-cli: {}", err))?;

        let output = child.wait_with_output().await?;

        if output.status.success() {
            Ok(serde_json::from_slice(&output.stdout)?)
        } else {
            error!("nitro-cli failed ({})", output.status);

            let stderr = String::from_utf8(output.stderr)?;
            error!("stderr:\n{}", stderr);

            for path in stderr.lines().filter_map(|line| {
                line.strip_prefix(
                    "If you open a support ticket, please provide the error log found at \"",
                )
                .and_then(|l| l.strip_suffix('"'))
            }) {
                let contents = std::fs::read_to_string(path)?;
                error!("{path}:\n{contents}");
            }

            Err(anyhow!("failed to run enclave"))
        }
    }

    pub async fn run_enclave(&self, args: RunEnclaveArgs) -> Result<EnclaveInfo> {
        self.run_and_deserialize_output(args).await
    }

    pub async fn describe_enclaves(&self) -> Result<Vec<EnclaveInfo>> {
        self.run_and_deserialize_output(DescribeEnclavesArgs {})
            .await
    }

    pub async fn terminate_enclave(&self, enclave_id: &str) -> Result<()> {
        let res: EnclaveTerminationStatus = self
            .run_and_deserialize_output(TerminateEnclaveArgs {
                enclave_id: enclave_id.to_string(),
            })
            .await?;

        match res.terminated {
            true => Ok(()),
            false => Err(anyhow!("nitro-cli failed to terminate enclave")),
        }
    }

    pub async fn describe_eif(&self, eif_path: &Path) -> Result<EIFInfo> {
        self.run_and_deserialize_output(DescribeEifArgs {
            eif_path: eif_path.to_path_buf(),
        })
        .await
    }

    pub async fn console(&self, enclave_id: &str) -> Result<ChildStdout> {
        let cmd_args = AttachConsoleArgs {
            enclave_id: enclave_id.to_string(),
        }
        .to_args()?;

        debug!("executing nitro-cli with args: {cmd_args:#?}");

        let child = Command::new(&self.program)
            .args(cmd_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| anyhow!("failed to execute nitro-cli: {err}"))?;

        Ok(child.stdout.unwrap())
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EIFInfo {
    #[serde(rename = "Measurements")]
    pub measurements: EIFMeasurements,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EIFMeasurements {
    #[serde(rename = "PCR0")]
    pub pcr0: String,

    #[serde(rename = "PCR1")]
    pub pcr1: String,

    #[serde(rename = "PCR2")]
    pub pcr2: String,

    #[serde(rename = "PCR8", skip_serializing_if = "Option::is_none")]
    pub pcr8: Option<String>,
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct EnclaveInfo {
    #[serde(rename = "EnclaveName")]
    pub name: String,

    #[serde(rename = "EnclaveID")]
    pub id: String,

    #[serde(rename = "ProcessID")]
    pub process_id: i32,

    #[serde(rename = "EnclaveCID")]
    pub cid: u32,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnclaveTerminationStatus {
    #[serde(rename = "EnclaveID")]
    pub id: String,

    #[serde(rename = "Terminated")]
    pub terminated: bool,
}

pub trait NitroCLIArgs {
    fn to_args(&self) -> Result<Vec<OsString>>;
}

pub struct RunEnclaveArgs {
    pub cpu_count: i32,
    pub memory_mb: i32,
    pub eif_path: PathBuf,
    pub cid: Option<u32>,
    pub debug_mode: bool,
}

impl NitroCLIArgs for RunEnclaveArgs {
    fn to_args(&self) -> Result<Vec<OsString>> {
        let mut args = vec![OsString::from("run-enclave")];

        if self.cpu_count < 1 {
            return Err(anyhow!(
                "at least 1 CPU is required, got: {}",
                self.cpu_count
            ));
        } else {
            args.push("--cpu-count".into());
            args.push(format!("{}", self.cpu_count).into());
        }

        if self.memory_mb < 64 {
            return Err(anyhow!(
                "at least 64MiB of memory are required, got: {}",
                self.memory_mb
            ));
        } else {
            args.push("--memory".into());
            args.push(format!("{}", self.memory_mb).into());
        }

        args.push("--eif-path".into());
        args.push(self.eif_path.clone().into());

        if let Some(cid) = self.cid {
            args.push("--enclave-cid".into());
            args.push(format!("{}", cid).into());
        }

        if self.debug_mode {
            args.push("--debug-mode".into());
        }

        Ok(args)
    }
}

pub struct DescribeEnclavesArgs {}

impl NitroCLIArgs for DescribeEnclavesArgs {
    fn to_args(&self) -> Result<Vec<OsString>> {
        Ok(vec![OsString::from("describe-enclaves")])
    }
}

pub struct TerminateEnclaveArgs {
    pub enclave_id: String,
}

impl NitroCLIArgs for TerminateEnclaveArgs {
    fn to_args(&self) -> Result<Vec<OsString>> {
        Ok(vec![
            OsString::from("terminate-enclave"),
            OsString::from("--enclave-id"),
            OsString::from(&self.enclave_id),
        ])
    }
}

pub struct AttachConsoleArgs {
    pub enclave_id: String,
}

impl NitroCLIArgs for AttachConsoleArgs {
    fn to_args(&self) -> Result<Vec<OsString>> {
        Ok(vec![
            OsString::from("console"),
            OsString::from("--enclave-id"),
            OsString::from(&self.enclave_id),
        ])
    }
}

pub struct DescribeEifArgs {
    pub eif_path: PathBuf,
}

impl NitroCLIArgs for DescribeEifArgs {
    fn to_args(&self) -> Result<Vec<OsString>> {
        Ok(vec![
            OsString::from("describe-eif"),
            OsString::from("--eif-path"),
            OsString::from(&self.eif_path),
        ])
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum KnownIssue {
    ImageTooLargeForRAM,
    OutOfDiskSpace,
}

impl KnownIssue {
    pub fn helpful_message(&self) -> &str {
        match self {
            KnownIssue::ImageTooLargeForRAM => {
                r#"This often means that insufficient memory was available to convert the source
image to an EIF. Consider shrinking the image, or re-running this command on a
machine with more memory available."#
            }
            KnownIssue::OutOfDiskSpace => {
                r#"Not enough disk space was available to convert the source image to an EIF. Note
that enclaver output images contain EIF files, which are potentially very
large. If you have been doing a lot of enclaver builds, consider cleaning up
old images in your local Docker engine."#
            }
        }
    }

    pub fn detect(line: &str) -> Option<Self> {
        // See: https://github.com/aws/aws-nitro-enclaves-cli/issues/282
        if line.contains(r#"rootfs/tmp\n  cmd\n  env\nCreate outputs:\n""#) {
            return Some(KnownIssue::ImageTooLargeForRAM);
        }

        if line.contains("no space left on device") {
            return Some(KnownIssue::OutOfDiskSpace);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_known_issues() {
        assert_eq!(KnownIssue::detect("foobar"), None);
        assert_eq!(
            KnownIssue::detect(
                r#"Linuxkit reported an error while creating the customer ramfs: "Add init containers:\nProcess init image: docker.io/library/1c505109-3417-4eec-9386-413dc32d4206\ntime=\"2022-10-20T22:13:33Z\" level=fatal msg=\"Failed to build init tarball from docker.io/library/1c505109-3417-4eec-9386-413dc32d4206: write /tmp/170765991: no space left on device\"\n""#
            ),
            Some(KnownIssue::OutOfDiskSpace)
        );
        assert_eq!(
            KnownIssue::detect(
                r#"Linuxkit reported an error while creating the customer ramfs: "Add init containers:\nProcess init image: docker.io/library/79ac5a4b-6e92-4e83-a351-ebdb2ff97d18\nAdd files:\n  rootfs/dev\n  rootfs/run\n  rootfs/sys\n  rootfs/var\n  rootfs/proc\n  rootfs/tmp\n  cmd\n  env\nCreate outputs:\n""#
            ),
            Some(KnownIssue::ImageTooLargeForRAM)
        );
    }
}

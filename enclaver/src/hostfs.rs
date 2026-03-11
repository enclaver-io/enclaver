use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use nix::fcntl::{FlockArg, flock};
use uuid::Uuid;

use crate::manifest::Manifest;

const HOSTFS_META_DIR: &str = ".enclaver-hostfs";
pub const CONTAINER_HOSTFS_ROOT: &str = "/mnt/enclaver-hostfs-data";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimeMountBinding {
    pub name: String,
    pub host_path: PathBuf,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LoopbackMountRequest {
    pub name: String,
    pub host_state_dir: PathBuf,
    pub container_mount_path: PathBuf,
    pub enclave_mount_path: PathBuf,
    pub size_mb: u64,
    pub required: bool,
}

#[derive(Debug)]
pub struct PreparedLoopbackMount {
    request: LoopbackMountRequest,
    host_mount_path: PathBuf,
    runtime_dir: PathBuf,
    _lock_file: File,
    mounted: bool,
}

impl PreparedLoopbackMount {
    pub fn container_bind(&self) -> String {
        format!(
            "{}:{}:rw",
            self.host_mount_path.display(),
            self.request.container_mount_path.display(),
        )
    }

    pub fn cleanup(&mut self) -> Result<()> {
        let mut first_error = None;

        if self.mounted {
            if let Err(err) = run_command("umount", [self.host_mount_path.as_os_str()]) {
                first_error = Some(err);
            } else {
                self.mounted = false;
            }
        }

        if self.runtime_dir.exists() {
            if let Err(err) = fs::remove_dir_all(&self.runtime_dir) {
                let err = anyhow!(
                    "failed to remove hostfs runtime dir {}: {err}",
                    self.runtime_dir.display()
                );
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }

        if let Some(err) = first_error {
            return Err(err);
        }

        Ok(())
    }
}

impl Drop for PreparedLoopbackMount {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub fn parse_runtime_mount_binding(spec: &str) -> Result<RuntimeMountBinding> {
    let (name, host_path) = spec
        .split_once('=')
        .ok_or_else(|| anyhow!("mount specification '{spec}' must be NAME=HOST_PATH"))?;
    let name = name.trim();
    let host_path = host_path.trim();

    if name.is_empty() {
        bail!("mount specification '{spec}' is missing the mount name");
    }
    if host_path.is_empty() {
        bail!("mount specification '{spec}' is missing the host path");
    }

    Ok(RuntimeMountBinding {
        name: name.to_string(),
        host_path: PathBuf::from(host_path),
    })
}

pub fn resolve_loopback_mounts(
    manifest: &Manifest,
    bindings: &[RuntimeMountBinding],
) -> Result<Vec<LoopbackMountRequest>> {
    let mut bindings_by_name = HashMap::new();
    for binding in bindings {
        let key = binding.name.trim().to_ascii_lowercase();
        if bindings_by_name.insert(key.clone(), binding).is_some() {
            bail!("duplicate runtime --mount binding for '{}'", binding.name);
        }
    }

    let mounts = manifest.hostfs_mounts().unwrap_or(&[]);

    if !bindings.is_empty() && mounts.is_empty() {
        bail!("runtime --mount bindings were provided, but the manifest defines no storage.mounts");
    }

    for binding in bindings {
        let exists = mounts
            .iter()
            .any(|mount| mount.name.eq_ignore_ascii_case(binding.name.trim()));
        if !exists {
            bail!(
                "runtime --mount binding '{}' has no matching entry in storage.mounts",
                binding.name
            );
        }
    }

    let mut requests = Vec::new();
    for mount in mounts {
        let Some(binding) = bindings_by_name.get(&mount.name.trim().to_ascii_lowercase()) else {
            if mount.required {
                bail!(
                    "required storage.mounts entry '{}' is missing a runtime --mount binding",
                    mount.name
                );
            }
            continue;
        };

        requests.push(LoopbackMountRequest {
            name: mount.name.clone(),
            host_state_dir: binding.host_path.clone(),
            container_mount_path: PathBuf::from(CONTAINER_HOSTFS_ROOT).join(&mount.name),
            enclave_mount_path: mount.mount_path.clone(),
            size_mb: mount.size_mb,
            required: mount.required,
        });
    }

    Ok(requests)
}

pub fn prepare_loopback_mounts(
    requests: &[LoopbackMountRequest],
) -> Result<Vec<PreparedLoopbackMount>> {
    let mut mounts = Vec::with_capacity(requests.len());
    for request in requests {
        match prepare_loopback_mount(request.clone()) {
            Ok(mount) => mounts.push(mount),
            Err(err) => {
                for mount in &mut mounts {
                    let _ = mount.cleanup();
                }
                return Err(err);
            }
        }
    }
    Ok(mounts)
}

fn prepare_loopback_mount(request: LoopbackMountRequest) -> Result<PreparedLoopbackMount> {
    if request.host_state_dir.exists() {
        if !request.host_state_dir.is_dir() {
            bail!(
                "host path for mount '{}' must be a directory: {}",
                request.name,
                request.host_state_dir.display()
            );
        }
    } else {
        fs::create_dir_all(&request.host_state_dir).with_context(|| {
            format!(
                "failed to create host state dir for mount '{}': {}",
                request.name,
                request.host_state_dir.display()
            )
        })?;
    }

    let meta_dir = request.host_state_dir.join(HOSTFS_META_DIR);
    fs::create_dir_all(&meta_dir).with_context(|| {
        format!(
            "failed to create hostfs metadata directory for mount '{}': {}",
            request.name,
            meta_dir.display()
        )
    })?;

    let lock_path = meta_dir.join("lock");
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| {
            format!(
                "failed to open hostfs lock file for mount '{}': {}",
                request.name,
                lock_path.display()
            )
        })?;
    flock(lock_file.as_raw_fd(), FlockArg::LockExclusiveNonblock).with_context(|| {
        format!(
            "hostfs backing store for mount '{}' is already in use: {}",
            request.name,
            request.host_state_dir.display()
        )
    })?;

    let image_path = meta_dir.join("disk.img");
    let expected_bytes = request
        .size_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow!("loopback size_mb overflows for mount '{}'", request.name))?;

    let image_exists = image_path.exists();
    if image_exists {
        let actual_bytes = fs::metadata(&image_path)
            .with_context(|| format!("failed to stat loopback image {}", image_path.display()))?
            .len();
        if actual_bytes != expected_bytes {
            bail!(
                "existing loopback image for mount '{}' has size {} bytes, expected {} bytes: {}",
                request.name,
                actual_bytes,
                expected_bytes,
                image_path.display()
            );
        }
    } else {
        let image_file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&image_path)
            .with_context(|| {
                format!(
                    "failed to create loopback image for mount '{}': {}",
                    request.name,
                    image_path.display()
                )
            })?;
        image_file.set_len(expected_bytes).with_context(|| {
            format!(
                "failed to size loopback image for mount '{}': {}",
                request.name,
                image_path.display()
            )
        })?;
        run_command("mkfs.ext4", ["-F".as_ref(), image_path.as_os_str()]).with_context(|| {
            format!(
                "failed to format loopback image for mount '{}': {}",
                request.name,
                image_path.display()
            )
        })?;
    }

    let runtime_dir = meta_dir.join(format!("mnt-{}", Uuid::new_v4()));
    let host_mount_path = runtime_dir.join("data");
    fs::create_dir_all(&host_mount_path).with_context(|| {
        format!(
            "failed to create loopback mountpoint for mount '{}': {}",
            request.name,
            host_mount_path.display()
        )
    })?;

    if let Err(err) = run_command(
        "mount",
        [
            "-o".as_ref(),
            OsStr::new("loop"),
            "-t".as_ref(),
            "ext4".as_ref(),
            image_path.as_os_str(),
            host_mount_path.as_os_str(),
        ],
    ) {
        let _ = fs::remove_dir_all(&runtime_dir);
        return Err(err).with_context(|| {
            format!(
                "failed to mount loopback image for mount '{}' at {}",
                request.name,
                host_mount_path.display()
            )
        });
    }

    Ok(PreparedLoopbackMount {
        request,
        host_mount_path,
        runtime_dir,
        _lock_file: lock_file,
        mounted: true,
    })
}

fn run_command<I, S>(program: &str, args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute '{program}'"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "no output".to_string()
    };
    bail!("command '{program}' failed: {detail}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{HostFsMountConfig, Manifest, Sources, Storage};

    #[test]
    fn parse_runtime_mount_binding_accepts_name_and_path() {
        let binding = parse_runtime_mount_binding("appdata=/var/lib/appdata").unwrap();
        assert_eq!(binding.name, "appdata");
        assert_eq!(binding.host_path, PathBuf::from("/var/lib/appdata"));
    }

    #[test]
    fn parse_runtime_mount_binding_rejects_missing_separator() {
        assert!(parse_runtime_mount_binding("appdata").is_err());
    }

    #[test]
    fn resolve_loopback_mounts_matches_manifest_mounts() {
        let manifest = Manifest {
            version: "v1".to_string(),
            name: "test".to_string(),
            target: "target:latest".to_string(),
            sources: Sources {
                app: "app:latest".to_string(),
                odyn: None,
                sleeve: None,
            },
            signature: None,
            ingress: None,
            egress: None,
            defaults: None,
            api: None,
            aux_api: None,
            vsock_ports: None,
            storage: Some(Storage {
                s3: None,
                mounts: Some(vec![HostFsMountConfig {
                    name: "appdata".to_string(),
                    mount_path: PathBuf::from("/mnt/appdata"),
                    required: true,
                    size_mb: 64,
                }]),
            }),
            kms_integration: None,
            helios_rpc: None,
            clock_sync: None,
        };

        let requests = resolve_loopback_mounts(
            &manifest,
            &[RuntimeMountBinding {
                name: "appdata".to_string(),
                host_path: PathBuf::from("/var/lib/appdata"),
            }],
        )
        .unwrap();

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].name, "appdata");
        assert_eq!(requests[0].size_mb, 64);
        assert_eq!(
            requests[0].container_mount_path,
            PathBuf::from(CONTAINER_HOSTFS_ROOT).join("appdata")
        );
        assert_eq!(
            requests[0].enclave_mount_path,
            PathBuf::from("/mnt/appdata")
        );
    }

    #[test]
    fn resolve_loopback_mounts_rejects_unknown_binding() {
        let manifest = Manifest {
            version: "v1".to_string(),
            name: "test".to_string(),
            target: "target:latest".to_string(),
            sources: Sources {
                app: "app:latest".to_string(),
                odyn: None,
                sleeve: None,
            },
            signature: None,
            ingress: None,
            egress: None,
            defaults: None,
            api: None,
            aux_api: None,
            vsock_ports: None,
            storage: Some(Storage {
                s3: None,
                mounts: None,
            }),
            kms_integration: None,
            helios_rpc: None,
            clock_sync: None,
        };

        let err = resolve_loopback_mounts(
            &manifest,
            &[RuntimeMountBinding {
                name: "appdata".to_string(),
                host_path: PathBuf::from("/var/lib/appdata"),
            }],
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("manifest defines no storage.mounts")
        );
    }
}

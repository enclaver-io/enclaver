use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result as AnyhowResult, anyhow};
use enclaver::constants::{HOSTFS_VSOCK_PORT_BASE, HOSTFS_VSOCK_PORT_LIMIT};
use enclaver::hostfs_client::{HostFsClient, HostFsClientError};
use enclaver::manifest::HostFsMountConfig;
use enclaver::vsock::VMADDR_CID_HOST;
use fuse_mt::{
    CreatedEntry, DirectoryEntry, FileAttr, FileType, FilesystemMT, FuseMT, RequestInfo, Statfs,
};
use fuser::{BackgroundSession, MountOption};
use libc::{EEXIST, EINVAL, O_ACCMODE, O_RDONLY, O_TRUNC};
use log::{info, warn};
use nix::sys::stat::{Mode, SFlag, makedev, mknod};
use tokio::runtime::Handle;
use tokio_vsock::VsockStream;

use crate::config::Configuration;

const FUSE_DEVICE_PATH: &str = "/dev/fuse";
const FUSE_DEVICE_MAJOR: u64 = 10;
const FUSE_DEVICE_MINOR: u64 = 229;
const HOSTFS_MOUNT_TTL: Duration = Duration::from_secs(1);
const HOSTFS_BLOCK_SIZE: u32 = 4096;
const HOSTFS_MAX_NAME_LEN: u32 = 255;
const HOSTFS_THREADS: usize = 4;

pub struct HostFsMountService {
    _mounts: Vec<MountedHostFs>,
}

struct MountedHostFs {
    name: String,
    mount_path: PathBuf,
    _session: BackgroundSession,
}

struct HostFsFilesystem {
    mount_name: String,
    port: u32,
    runtime: Handle,
}

impl HostFsMountService {
    pub async fn start(config: &Configuration) -> AnyhowResult<Self> {
        let Some(mounts) = config.manifest.hostfs_mounts() else {
            return Ok(Self {
                _mounts: Vec::new(),
            });
        };
        if mounts.is_empty() {
            return Ok(Self {
                _mounts: Vec::new(),
            });
        }

        ensure_fuse_device()?;

        let mut active_mounts = Vec::new();
        for (index, mount) in mounts.iter().enumerate() {
            let port = HOSTFS_VSOCK_PORT_BASE
                .checked_add(index as u32)
                .ok_or_else(|| anyhow!("hostfs port allocation overflowed"))?;
            if port > HOSTFS_VSOCK_PORT_LIMIT {
                return Err(anyhow!(
                    "hostfs mount '{}' exceeds the configured vsock port range {}-{}",
                    mount.name,
                    HOSTFS_VSOCK_PORT_BASE,
                    HOSTFS_VSOCK_PORT_LIMIT
                ));
            }

            match MountedHostFs::start(mount, port).await {
                Ok(active) => active_mounts.push(active),
                Err(err) if !mount.required => {
                    warn!(
                        "optional hostfs mount '{}' could not be started: {err:#}",
                        mount.name
                    );
                }
                Err(err) => {
                    return Err(err.context(format!(
                        "failed to start required hostfs mount '{}'",
                        mount.name
                    )));
                }
            }
        }

        Ok(Self {
            _mounts: active_mounts,
        })
    }
}

impl MountedHostFs {
    async fn start(mount: &HostFsMountConfig, port: u32) -> AnyhowResult<Self> {
        if mount.mount_path.exists() {
            if !mount.mount_path.is_dir() {
                return Err(anyhow!(
                    "hostfs mount path exists but is not a directory: {}",
                    mount.mount_path.display()
                ));
            }
        } else {
            std::fs::create_dir_all(&mount.mount_path).with_context(|| {
                format!(
                    "failed to create hostfs mount path {}",
                    mount.mount_path.display()
                )
            })?;
        }

        let mut probe = connect_client(&mount.name, port)
            .await
            .with_context(|| format!("failed to connect to hostfs proxy on vsock port {}", port))?;

        if probe.read_only() {
            return Err(anyhow!(
                "hostfs mount '{}' unexpectedly connected to a read-only host proxy",
                mount.name
            ));
        }
        probe.ping().await.context("hostfs ping failed")?;
        drop(probe);

        let filesystem = HostFsFilesystem {
            mount_name: mount.name.clone(),
            port,
            runtime: Handle::current(),
        };

        let mut options = vec![
            MountOption::FSName(format!("hostfs-{}", mount.name)),
            MountOption::Subtype("hostfs".to_string()),
            MountOption::NoDev,
            MountOption::NoSuid,
            MountOption::NoExec,
            MountOption::DefaultPermissions,
            MountOption::RW,
        ];

        let session = fuser::spawn_mount2(
            FuseMT::new(filesystem, HOSTFS_THREADS),
            &mount.mount_path,
            &options,
        )
        .with_context(|| {
            format!(
                "failed to mount hostfs '{}' at {}",
                mount.name,
                mount.mount_path.display()
            )
        })?;

        info!(
            "mounted hostfs '{}' at {} via vsock port {}",
            mount.name,
            mount.mount_path.display(),
            port
        );

        Ok(Self {
            name: mount.name.clone(),
            mount_path: mount.mount_path.clone(),
            _session: session,
        })
    }
}

impl Drop for MountedHostFs {
    fn drop(&mut self) {
        info!(
            "unmounting hostfs '{}' from {}",
            self.name,
            self.mount_path.display()
        );
    }
}

impl HostFsFilesystem {
    fn errno_from_client(err: HostFsClientError) -> libc::c_int {
        err.errno()
    }

    fn relative_path(path: &Path) -> std::result::Result<String, libc::c_int> {
        if path == Path::new("/") {
            return Ok(String::new());
        }

        let stripped = if path.is_absolute() {
            path.strip_prefix("/").map_err(|_| EINVAL)?
        } else {
            path
        };

        stripped.to_str().map(str::to_owned).ok_or(EINVAL)
    }

    fn child_path(parent: &Path, name: &OsStr) -> std::result::Result<PathBuf, libc::c_int> {
        if name.is_empty() {
            return Err(EINVAL);
        }
        Ok(parent.join(name))
    }

    fn with_client_async<T>(
        &self,
        op: impl for<'a> FnOnce(
            &'a mut HostFsClient<VsockStream>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = std::result::Result<T, HostFsClientError>>
                    + Send
                    + 'a,
            >,
        > + Send
        + 'static,
    ) -> std::result::Result<T, libc::c_int> {
        let mount_name = self.mount_name.clone();
        let port = self.port;

        self.runtime.block_on(async move {
            let mut client = connect_client(&mount_name, port)
                .await
                .map_err(HostFsFilesystem::errno_from_client)?;
            op(&mut client)
                .await
                .map_err(HostFsFilesystem::errno_from_client)
        })
    }

    fn metadata_attr(&self, path: &Path) -> std::result::Result<(Duration, FileAttr), libc::c_int> {
        let relative = Self::relative_path(path)?;
        let metadata = self.with_client_async(move |client| Box::pin(client.metadata(relative)))?;
        Ok((HOSTFS_MOUNT_TTL, metadata_to_attr(&metadata)))
    }
}

impl FilesystemMT for HostFsFilesystem {
    fn getattr(&self, _req: RequestInfo, path: &Path, _fh: Option<u64>) -> fuse_mt::ResultEntry {
        self.metadata_attr(path)
    }

    fn truncate(
        &self,
        _req: RequestInfo,
        path: &Path,
        _fh: Option<u64>,
        size: u64,
    ) -> fuse_mt::ResultEmpty {
        let relative = Self::relative_path(path)?;
        self.with_client_async(move |client| Box::pin(client.set_len(relative, size)))
    }

    fn mkdir(
        &self,
        _req: RequestInfo,
        parent: &Path,
        name: &OsStr,
        _mode: u32,
    ) -> fuse_mt::ResultEntry {
        let child = Self::child_path(parent, name)?;
        let relative = Self::relative_path(&child)?;
        self.with_client_async(move |client| Box::pin(client.mkdir(relative, false)))?;
        self.metadata_attr(&child)
    }

    fn unlink(&self, _req: RequestInfo, parent: &Path, name: &OsStr) -> fuse_mt::ResultEmpty {
        let child = Self::child_path(parent, name)?;
        let relative = Self::relative_path(&child)?;
        self.with_client_async(move |client| Box::pin(client.remove_file(relative)))
    }

    fn rmdir(&self, _req: RequestInfo, parent: &Path, name: &OsStr) -> fuse_mt::ResultEmpty {
        let child = Self::child_path(parent, name)?;
        let relative = Self::relative_path(&child)?;
        self.with_client_async(move |client| Box::pin(client.remove_dir(relative)))
    }

    fn rename(
        &self,
        _req: RequestInfo,
        parent: &Path,
        name: &OsStr,
        newparent: &Path,
        newname: &OsStr,
    ) -> fuse_mt::ResultEmpty {
        let from = Self::relative_path(&Self::child_path(parent, name)?)?;
        let to = Self::relative_path(&Self::child_path(newparent, newname)?)?;
        self.with_client_async(move |client| Box::pin(client.rename(from, to)))
    }

    fn open(&self, _req: RequestInfo, path: &Path, flags: u32) -> fuse_mt::ResultOpen {
        let relative = Self::relative_path(path)?;
        let wants_write = (flags as i32 & O_ACCMODE) != O_RDONLY;
        if wants_write && (flags as i32 & O_TRUNC) != 0 {
            self.with_client_async(move |client| Box::pin(client.set_len(relative, 0)))?;
        }
        Ok((0, 0))
    }

    fn read(
        &self,
        _req: RequestInfo,
        path: &Path,
        _fh: u64,
        offset: u64,
        size: u32,
        callback: impl FnOnce(fuse_mt::ResultSlice<'_>) -> fuse_mt::CallbackResult,
    ) -> fuse_mt::CallbackResult {
        let result = (|| -> std::result::Result<Vec<u8>, libc::c_int> {
            let relative = Self::relative_path(path)?;
            self.with_client_async(move |client| Box::pin(client.read_file(relative, offset, size)))
        })();

        match result {
            Ok(data) => callback(Ok(&data)),
            Err(errno) => callback(Err(errno)),
        }
    }

    fn write(
        &self,
        _req: RequestInfo,
        path: &Path,
        _fh: u64,
        offset: u64,
        data: Vec<u8>,
        _flags: u32,
    ) -> fuse_mt::ResultWrite {
        let relative = Self::relative_path(path)?;
        self.with_client_async(move |client| {
            Box::pin(async move {
                let written = client
                    .write_file(relative, offset, data, false, false)
                    .await?;
                Ok(written as u32)
            })
        })
    }

    fn flush(
        &self,
        _req: RequestInfo,
        path: &Path,
        _fh: u64,
        _lock_owner: u64,
    ) -> fuse_mt::ResultEmpty {
        let relative = Self::relative_path(path)?;
        self.with_client_async(move |client| Box::pin(client.fsync(relative)))
    }

    fn release(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _fh: u64,
        _flags: u32,
        _lock_owner: u64,
        _flush: bool,
    ) -> fuse_mt::ResultEmpty {
        Ok(())
    }

    fn fsync(
        &self,
        _req: RequestInfo,
        path: &Path,
        _fh: u64,
        _datasync: bool,
    ) -> fuse_mt::ResultEmpty {
        let relative = Self::relative_path(path)?;
        self.with_client_async(move |client| Box::pin(client.fsync(relative)))
    }

    fn opendir(&self, _req: RequestInfo, _path: &Path, _flags: u32) -> fuse_mt::ResultOpen {
        Ok((0, 0))
    }

    fn readdir(&self, _req: RequestInfo, path: &Path, _fh: u64) -> fuse_mt::ResultReaddir {
        let relative = Self::relative_path(path)?;
        let mut entries = vec![
            DirectoryEntry {
                name: ".".into(),
                kind: FileType::Directory,
            },
            DirectoryEntry {
                name: "..".into(),
                kind: FileType::Directory,
            },
        ];

        let remote_entries =
            self.with_client_async(move |client| Box::pin(client.read_dir(relative)))?;
        entries.extend(remote_entries.into_iter().map(|entry| DirectoryEntry {
            name: entry.name.into(),
            kind: entry_type_to_fuser(entry.entry_type),
        }));
        Ok(entries)
    }

    fn releasedir(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _fh: u64,
        _flags: u32,
    ) -> fuse_mt::ResultEmpty {
        Ok(())
    }

    fn fsyncdir(
        &self,
        _req: RequestInfo,
        path: &Path,
        _fh: u64,
        _datasync: bool,
    ) -> fuse_mt::ResultEmpty {
        let relative = Self::relative_path(path)?;
        self.with_client_async(move |client| Box::pin(client.fsync(relative)))
    }

    fn statfs(&self, _req: RequestInfo, _path: &Path) -> fuse_mt::ResultStatfs {
        let stat = self.with_client_async(|client| Box::pin(client.statfs()))?;
        let blocks = stat.total_bytes.div_ceil(HOSTFS_BLOCK_SIZE as u64);
        let free_blocks = stat.available_bytes.div_ceil(HOSTFS_BLOCK_SIZE as u64);
        Ok(Statfs {
            blocks,
            bfree: free_blocks,
            bavail: free_blocks,
            files: 0,
            ffree: 0,
            bsize: HOSTFS_BLOCK_SIZE,
            namelen: HOSTFS_MAX_NAME_LEN,
            frsize: HOSTFS_BLOCK_SIZE,
        })
    }

    fn access(&self, _req: RequestInfo, path: &Path, _mask: u32) -> fuse_mt::ResultEmpty {
        self.metadata_attr(path).map(|_| ())
    }

    fn create(
        &self,
        _req: RequestInfo,
        parent: &Path,
        name: &OsStr,
        _mode: u32,
        flags: u32,
    ) -> fuse_mt::ResultCreate {
        let child = Self::child_path(parent, name)?;
        let relative = Self::relative_path(&child)?;

        match self.with_client_async({
            let relative = relative.clone();
            move |client| Box::pin(client.metadata(relative))
        }) {
            Ok(_) => return Err(EEXIST),
            Err(errno) if errno == libc::ENOENT => {}
            Err(errno) => return Err(errno),
        }

        self.with_client_async({
            let relative = relative.clone();
            move |client| Box::pin(client.write_file(relative, 0, Vec::new(), true, false))
        })?;

        if (flags as i32 & O_TRUNC) != 0 {
            self.with_client_async({
                let relative = relative.clone();
                move |client| Box::pin(client.set_len(relative, 0))
            })?;
        }

        let (_ttl, attr) = self.metadata_attr(&child)?;
        Ok(CreatedEntry {
            ttl: HOSTFS_MOUNT_TTL,
            attr,
            fh: 0,
            flags: 0,
        })
    }
}

async fn connect_client(
    mount_name: &str,
    port: u32,
) -> std::result::Result<HostFsClient<VsockStream>, HostFsClientError> {
    let stream = VsockStream::connect(VMADDR_CID_HOST, port)
        .await
        .map_err(|err| HostFsClientError::Transport(err.into()))?;
    HostFsClient::connect(stream, mount_name).await
}

fn entry_type_to_file_type(entry_type: enclaver::fs_protocol::FsEntryType) -> FileType {
    match entry_type {
        enclaver::fs_protocol::FsEntryType::File => FileType::RegularFile,
        enclaver::fs_protocol::FsEntryType::Directory => FileType::Directory,
        enclaver::fs_protocol::FsEntryType::Symlink => FileType::Symlink,
        enclaver::fs_protocol::FsEntryType::Other => FileType::RegularFile,
    }
}

fn metadata_to_attr(metadata: &enclaver::fs_protocol::FsMetadata) -> FileAttr {
    let kind = entry_type_to_file_type(metadata.entry_type.clone());
    let perm = match kind {
        FileType::Directory => {
            if metadata.read_only {
                0o555
            } else {
                0o755
            }
        }
        FileType::RegularFile => {
            if metadata.read_only {
                0o444
            } else {
                0o644
            }
        }
        FileType::Symlink => 0o777,
        _ => 0o644,
    };

    let now = SystemTime::now();
    FileAttr {
        size: metadata.len,
        blocks: metadata.len.div_ceil(512),
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        kind,
        perm,
        nlink: if matches!(kind, FileType::Directory) {
            2
        } else {
            1
        },
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}

fn ensure_fuse_device() -> AnyhowResult<()> {
    let path = Path::new(FUSE_DEVICE_PATH);
    if path.exists() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    mknod(
        path,
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(0o666),
        makedev(FUSE_DEVICE_MAJOR, FUSE_DEVICE_MINOR),
    )
    .with_context(|| format!("failed to create {}", path.display()))?;

    Ok(())
}

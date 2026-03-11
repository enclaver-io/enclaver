use std::io;
use std::path::{Component, Path, PathBuf};

use anyhow::{Result, anyhow};
use nix::libc::{EINVAL, EIO, EROFS};
use nix::sys::statvfs::statvfs;
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncRead, AsyncSeekExt, AsyncWrite};

use crate::fs_protocol::{
    FsDirEntry, FsEntryType, FsMetadata, FsProxyError, FsProxyRequest, FsProxyResponse, FsStat,
    HOSTFS_PROTOCOL_VERSION, HelloResponse, recv_msg, send_msg,
};

pub struct HostFsService {
    mount_name: String,
    root: PathBuf,
    read_only: bool,
}

impl HostFsService {
    pub fn new(
        mount_name: impl Into<String>,
        root: impl Into<PathBuf>,
        read_only: bool,
    ) -> Result<Self> {
        let mount_name = mount_name.into();
        if mount_name.trim().is_empty() {
            return Err(anyhow!("hostfs mount_name must not be empty"));
        }

        let root = std::fs::canonicalize(root.into())?;
        if !root.is_dir() {
            return Err(anyhow!(
                "hostfs root for mount '{}' must be a directory: {}",
                mount_name,
                root.display()
            ));
        }

        Ok(Self {
            mount_name,
            root,
            read_only,
        })
    }

    pub async fn serve_conn<S>(&self, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);

        let hello = match recv_msg::<_, FsProxyRequest>(&mut reader).await? {
            FsProxyRequest::Hello(hello) => hello,
            _ => {
                let response = FsProxyResponse::Error(FsProxyError::new(
                    Some(EINVAL),
                    "first hostfs message must be hello",
                ));
                send_msg(&mut writer, &response).await?;
                return Ok(());
            }
        };

        if hello.protocol_version != HOSTFS_PROTOCOL_VERSION {
            let response = FsProxyResponse::Error(FsProxyError::new(
                Some(EINVAL),
                format!(
                    "unsupported hostfs protocol version {} (expected {})",
                    hello.protocol_version, HOSTFS_PROTOCOL_VERSION
                ),
            ));
            send_msg(&mut writer, &response).await?;
            return Ok(());
        }

        if hello.mount_name != self.mount_name {
            let response = FsProxyResponse::Error(FsProxyError::new(
                Some(EINVAL),
                format!(
                    "hostfs mount name mismatch: got '{}', expected '{}'",
                    hello.mount_name, self.mount_name
                ),
            ));
            send_msg(&mut writer, &response).await?;
            return Ok(());
        }

        send_msg(
            &mut writer,
            &FsProxyResponse::Hello(HelloResponse {
                protocol_version: HOSTFS_PROTOCOL_VERSION,
                mount_name: self.mount_name.clone(),
                read_only: self.read_only,
            }),
        )
        .await?;

        loop {
            let request = match recv_msg::<_, FsProxyRequest>(&mut reader).await {
                Ok(request) => request,
                Err(err) if is_unexpected_eof(&err) => break,
                Err(err) => return Err(err),
            };

            let response = match self.handle_request(request).await {
                Ok(response) => response,
                Err(err) => FsProxyResponse::Error(err),
            };

            send_msg(&mut writer, &response).await?;
        }

        Ok(())
    }

    async fn handle_request(
        &self,
        request: FsProxyRequest,
    ) -> std::result::Result<FsProxyResponse, FsProxyError> {
        match request {
            FsProxyRequest::Hello(_) => Err(invalid_input("hello may only be sent once")),
            FsProxyRequest::Ping => Ok(FsProxyResponse::Pong),
            FsProxyRequest::StatFs => self.handle_statfs().await,
            FsProxyRequest::GetMetadata { path } => self.handle_metadata(&path).await,
            FsProxyRequest::ReadDir { path } => self.handle_read_dir(&path).await,
            FsProxyRequest::ReadFile { path, offset, len } => {
                self.handle_read_file(&path, offset, len).await
            }
            FsProxyRequest::WriteFile {
                path,
                offset,
                data,
                create,
                truncate,
            } => {
                self.ensure_writable()?;
                self.handle_write_file(&path, offset, &data, create, truncate)
                    .await
            }
            FsProxyRequest::SetLen { path, size } => {
                self.ensure_writable()?;
                self.handle_set_len(&path, size).await
            }
            FsProxyRequest::Mkdir { path, recursive } => {
                self.ensure_writable()?;
                self.handle_mkdir(&path, recursive).await
            }
            FsProxyRequest::RemoveFile { path } => {
                self.ensure_writable()?;
                self.handle_remove_file(&path).await
            }
            FsProxyRequest::RemoveDir { path } => {
                self.ensure_writable()?;
                self.handle_remove_dir(&path).await
            }
            FsProxyRequest::Rename { from, to } => {
                self.ensure_writable()?;
                self.handle_rename(&from, &to).await
            }
            FsProxyRequest::Fsync { path } => self.handle_fsync(&path).await,
        }
    }

    async fn handle_statfs(&self) -> std::result::Result<FsProxyResponse, FsProxyError> {
        let root = self.root.clone();
        let stat = tokio::task::spawn_blocking(move || statvfs(&root))
            .await
            .map_err(join_error_to_proxy_error)?
            .map_err(nix_error_to_proxy_error)?;

        let fragment_size = stat.fragment_size() as u64;
        Ok(FsProxyResponse::StatFs(FsStat {
            total_bytes: stat.blocks() as u64 * fragment_size,
            available_bytes: stat.blocks_available() as u64 * fragment_size,
        }))
    }

    async fn handle_metadata(
        &self,
        path: &str,
    ) -> std::result::Result<FsProxyResponse, FsProxyError> {
        let resolved = self.resolve_path_preserving_leaf(path, true)?;
        let metadata = tokio::task::spawn_blocking(move || std::fs::symlink_metadata(&resolved))
            .await
            .map_err(join_error_to_proxy_error)?
            .map_err(io_error_to_proxy_error)?;

        Ok(FsProxyResponse::Metadata(metadata_to_wire(&metadata)))
    }

    async fn handle_read_dir(
        &self,
        path: &str,
    ) -> std::result::Result<FsProxyResponse, FsProxyError> {
        let resolved = self.resolve_existing_path(path)?;
        let mut dir = fs::read_dir(&resolved)
            .await
            .map_err(io_error_to_proxy_error)?;
        let mut entries = Vec::new();

        while let Some(entry) = dir.next_entry().await.map_err(io_error_to_proxy_error)? {
            let entry_type = entry.file_type().await.map_err(io_error_to_proxy_error)?;
            entries.push(FsDirEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                entry_type: file_type_to_entry_type(&entry_type),
            });
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(FsProxyResponse::ReadDir { entries })
    }

    async fn handle_read_file(
        &self,
        path: &str,
        offset: u64,
        len: u32,
    ) -> std::result::Result<FsProxyResponse, FsProxyError> {
        let resolved = self.resolve_existing_path(path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .open(&resolved)
            .await
            .map_err(io_error_to_proxy_error)?;
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(io_error_to_proxy_error)?;

        let mut data = vec![0u8; len as usize];
        let nread = tokio::io::AsyncReadExt::read(&mut file, &mut data)
            .await
            .map_err(io_error_to_proxy_error)?;
        data.truncate(nread);

        Ok(FsProxyResponse::ReadFile { data })
    }

    async fn handle_write_file(
        &self,
        path: &str,
        offset: u64,
        data: &[u8],
        create: bool,
        truncate: bool,
    ) -> std::result::Result<FsProxyResponse, FsProxyError> {
        let resolved = self.resolve_path_for_create(path)?;

        let mut options = OpenOptions::new();
        options.write(true).create(create).truncate(truncate);
        let mut file = options
            .open(&resolved)
            .await
            .map_err(io_error_to_proxy_error)?;
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(io_error_to_proxy_error)?;
        tokio::io::AsyncWriteExt::write_all(&mut file, data)
            .await
            .map_err(io_error_to_proxy_error)?;
        file.sync_data().await.map_err(io_error_to_proxy_error)?;

        Ok(FsProxyResponse::WriteFile {
            written: data.len() as u64,
        })
    }

    async fn handle_set_len(
        &self,
        path: &str,
        size: u64,
    ) -> std::result::Result<FsProxyResponse, FsProxyError> {
        let resolved = self.resolve_path_for_create(path)?;
        let file = OpenOptions::new()
            .write(true)
            .open(&resolved)
            .await
            .map_err(io_error_to_proxy_error)?;
        file.set_len(size).await.map_err(io_error_to_proxy_error)?;
        file.sync_all().await.map_err(io_error_to_proxy_error)?;
        Ok(FsProxyResponse::Ok)
    }

    async fn handle_mkdir(
        &self,
        path: &str,
        recursive: bool,
    ) -> std::result::Result<FsProxyResponse, FsProxyError> {
        let resolved = self.resolve_path_for_create(path)?;
        if recursive {
            fs::create_dir_all(&resolved)
                .await
                .map_err(io_error_to_proxy_error)?;
        } else {
            fs::create_dir(&resolved)
                .await
                .map_err(io_error_to_proxy_error)?;
        }
        Ok(FsProxyResponse::Ok)
    }

    async fn handle_remove_file(
        &self,
        path: &str,
    ) -> std::result::Result<FsProxyResponse, FsProxyError> {
        let resolved = self.resolve_path_preserving_leaf(path, false)?;
        fs::remove_file(&resolved)
            .await
            .map_err(io_error_to_proxy_error)?;
        Ok(FsProxyResponse::Ok)
    }

    async fn handle_remove_dir(
        &self,
        path: &str,
    ) -> std::result::Result<FsProxyResponse, FsProxyError> {
        let resolved = self.resolve_path_preserving_leaf(path, false)?;
        fs::remove_dir(&resolved)
            .await
            .map_err(io_error_to_proxy_error)?;
        Ok(FsProxyResponse::Ok)
    }

    async fn handle_rename(
        &self,
        from: &str,
        to: &str,
    ) -> std::result::Result<FsProxyResponse, FsProxyError> {
        let from = self.resolve_path_preserving_leaf(from, false)?;
        let to = self.resolve_path_for_create(to)?;
        fs::rename(&from, &to)
            .await
            .map_err(io_error_to_proxy_error)?;
        Ok(FsProxyResponse::Ok)
    }

    async fn handle_fsync(&self, path: &str) -> std::result::Result<FsProxyResponse, FsProxyError> {
        let resolved = self.resolve_existing_path(path)?;
        let file = OpenOptions::new()
            .read(true)
            .open(&resolved)
            .await
            .map_err(io_error_to_proxy_error)?;
        file.sync_all().await.map_err(io_error_to_proxy_error)?;
        Ok(FsProxyResponse::Ok)
    }

    fn ensure_writable(&self) -> std::result::Result<(), FsProxyError> {
        if self.read_only {
            Err(FsProxyError::new(
                Some(EROFS),
                format!("hostfs mount '{}' is read-only", self.mount_name),
            ))
        } else {
            Ok(())
        }
    }

    fn resolve_existing_path(&self, path: &str) -> std::result::Result<PathBuf, FsProxyError> {
        let relative = normalize_relative_path(path)?;
        self.resolve_follow_path(&relative)
    }

    fn resolve_follow_path(&self, relative: &Path) -> std::result::Result<PathBuf, FsProxyError> {
        let joined = self.root.join(relative);
        let canonical = std::fs::canonicalize(&joined).map_err(io_error_to_proxy_error)?;
        self.ensure_within_root(&canonical)?;
        Ok(canonical)
    }

    fn resolve_path_for_create(&self, path: &str) -> std::result::Result<PathBuf, FsProxyError> {
        let relative = normalize_relative_path(path)?;
        if relative.as_os_str().is_empty() {
            return Err(invalid_input("path must not refer to the mount root"));
        }

        let mut current = self.root.clone();
        for component in relative.components() {
            let Component::Normal(part) = component else {
                return Err(invalid_input("hostfs path contains an invalid component"));
            };
            current.push(part);
            if current.exists() {
                current = std::fs::canonicalize(&current).map_err(io_error_to_proxy_error)?;
                self.ensure_within_root(&current)?;
            }
        }

        Ok(current)
    }

    fn resolve_path_preserving_leaf(
        &self,
        path: &str,
        allow_root: bool,
    ) -> std::result::Result<PathBuf, FsProxyError> {
        let relative = normalize_relative_path(path)?;
        if relative.as_os_str().is_empty() {
            if allow_root {
                return Ok(self.root.clone());
            }
            return Err(invalid_input("path must not refer to the mount root"));
        }

        let parent = relative.parent().unwrap_or_else(|| Path::new(""));
        let parent = if parent.as_os_str().is_empty() {
            self.root.clone()
        } else {
            self.resolve_follow_path(parent)?
        };

        let leaf = relative
            .file_name()
            .ok_or_else(|| invalid_input("hostfs path must refer to a filesystem entry"))?;

        Ok(parent.join(leaf))
    }

    fn ensure_within_root(&self, path: &Path) -> std::result::Result<(), FsProxyError> {
        if path == self.root || path.starts_with(&self.root) {
            Ok(())
        } else {
            Err(invalid_input(format!(
                "hostfs path escapes mount root '{}'",
                self.mount_name
            )))
        }
    }
}

fn normalize_relative_path(path: &str) -> std::result::Result<PathBuf, FsProxyError> {
    let raw = path.trim();
    if raw.is_empty() || raw == "." {
        return Ok(PathBuf::new());
    }

    let input = Path::new(raw);
    if input.is_absolute() {
        return Err(invalid_input("hostfs paths must be relative"));
    }

    let mut normalized = PathBuf::new();
    for component in input.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(invalid_input("hostfs path traversal is not allowed"));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(invalid_input("hostfs paths must be relative"));
            }
        }
    }

    Ok(normalized)
}

fn metadata_to_wire(metadata: &std::fs::Metadata) -> FsMetadata {
    FsMetadata {
        entry_type: file_type_to_entry_type(&metadata.file_type()),
        len: metadata.len(),
        read_only: metadata.permissions().readonly(),
    }
}

fn file_type_to_entry_type(file_type: &std::fs::FileType) -> FsEntryType {
    if file_type.is_dir() {
        FsEntryType::Directory
    } else if file_type.is_file() {
        FsEntryType::File
    } else if file_type.is_symlink() {
        FsEntryType::Symlink
    } else {
        FsEntryType::Other
    }
}

fn invalid_input(message: impl Into<String>) -> FsProxyError {
    FsProxyError::new(Some(EINVAL), message.into())
}

fn io_error_to_proxy_error(err: io::Error) -> FsProxyError {
    FsProxyError::new(err.raw_os_error().or(Some(EIO)), err.to_string())
}

fn join_error_to_proxy_error(err: tokio::task::JoinError) -> FsProxyError {
    FsProxyError::new(Some(EIO), err.to_string())
}

fn nix_error_to_proxy_error(err: nix::Error) -> FsProxyError {
    FsProxyError::new(Some(err as i32), err.to_string())
}

fn is_unexpected_eof(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io_err| io_err.kind() == io::ErrorKind::UnexpectedEof)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_protocol::{
        FsProxyRequest, FsProxyResponse, HOSTFS_PROTOCOL_VERSION, HelloRequest,
    };
    use nix::libc::{EINVAL, EROFS};
    use tempfile::tempdir;
    use tokio::io::DuplexStream;

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    async fn connect(service: HostFsService) -> DuplexStream {
        let (client, server) = tokio::io::duplex(128 * 1024);
        tokio::spawn(async move {
            service.serve_conn(server).await.unwrap();
        });
        client
    }

    async fn hello(stream: &mut DuplexStream, mount_name: &str) -> FsProxyResponse {
        send_msg(
            stream,
            &FsProxyRequest::Hello(HelloRequest {
                protocol_version: HOSTFS_PROTOCOL_VERSION,
                mount_name: mount_name.to_string(),
            }),
        )
        .await
        .unwrap();
        recv_msg(stream).await.unwrap()
    }

    #[tokio::test]
    async fn writes_and_reads_files() {
        let root = tempdir().unwrap();
        let service = HostFsService::new("appdata", root.path(), false).unwrap();
        let mut client = connect(service).await;

        assert_eq!(
            hello(&mut client, "appdata").await,
            FsProxyResponse::Hello(HelloResponse {
                protocol_version: HOSTFS_PROTOCOL_VERSION,
                mount_name: "appdata".to_string(),
                read_only: false,
            })
        );

        send_msg(
            &mut client,
            &FsProxyRequest::Mkdir {
                path: "notes".to_string(),
                recursive: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            recv_msg::<_, FsProxyResponse>(&mut client).await.unwrap(),
            FsProxyResponse::Ok
        );

        send_msg(
            &mut client,
            &FsProxyRequest::WriteFile {
                path: "notes/hello.txt".to_string(),
                offset: 0,
                data: b"hello world".to_vec(),
                create: true,
                truncate: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            recv_msg::<_, FsProxyResponse>(&mut client).await.unwrap(),
            FsProxyResponse::WriteFile { written: 11 }
        );

        send_msg(
            &mut client,
            &FsProxyRequest::ReadFile {
                path: "notes/hello.txt".to_string(),
                offset: 0,
                len: 32,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            recv_msg::<_, FsProxyResponse>(&mut client).await.unwrap(),
            FsProxyResponse::ReadFile {
                data: b"hello world".to_vec(),
            }
        );
    }

    #[tokio::test]
    async fn rejects_path_traversal() {
        let root = tempdir().unwrap();
        let service = HostFsService::new("appdata", root.path(), false).unwrap();
        let mut client = connect(service).await;
        let _ = hello(&mut client, "appdata").await;

        send_msg(
            &mut client,
            &FsProxyRequest::ReadFile {
                path: "../secret.txt".to_string(),
                offset: 0,
                len: 8,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            recv_msg::<_, FsProxyResponse>(&mut client).await.unwrap(),
            FsProxyResponse::Error(FsProxyError::new(
                Some(EINVAL),
                "hostfs path traversal is not allowed",
            ))
        );
    }

    #[tokio::test]
    async fn rejects_writes_on_read_only_mounts() {
        let root = tempdir().unwrap();
        let service = HostFsService::new("appdata", root.path(), true).unwrap();
        let mut client = connect(service).await;
        let _ = hello(&mut client, "appdata").await;

        send_msg(
            &mut client,
            &FsProxyRequest::WriteFile {
                path: "hello.txt".to_string(),
                offset: 0,
                data: b"hello".to_vec(),
                create: true,
                truncate: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            recv_msg::<_, FsProxyResponse>(&mut client).await.unwrap(),
            FsProxyResponse::Error(FsProxyError::new(
                Some(EROFS),
                "hostfs mount 'appdata' is read-only",
            ))
        );
    }

    #[tokio::test]
    async fn reports_filesystem_capacity() {
        let root = tempdir().unwrap();
        let service = HostFsService::new("appdata", root.path(), false).unwrap();
        let mut client = connect(service).await;
        let _ = hello(&mut client, "appdata").await;

        send_msg(&mut client, &FsProxyRequest::StatFs)
            .await
            .unwrap();

        let FsProxyResponse::StatFs(stat) =
            recv_msg::<_, FsProxyResponse>(&mut client).await.unwrap()
        else {
            panic!("expected statfs response");
        };

        assert!(stat.total_bytes > 0);
        assert!(stat.available_bytes > 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remove_file_unlinks_symlink_without_touching_target() {
        let root = tempdir().unwrap();
        std::fs::write(root.path().join("target.txt"), b"hello").unwrap();
        symlink("target.txt", root.path().join("alias.txt")).unwrap();

        let service = HostFsService::new("appdata", root.path(), false).unwrap();
        let mut client = connect(service).await;
        let _ = hello(&mut client, "appdata").await;

        send_msg(
            &mut client,
            &FsProxyRequest::RemoveFile {
                path: "alias.txt".to_string(),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            recv_msg::<_, FsProxyResponse>(&mut client).await.unwrap(),
            FsProxyResponse::Ok
        );
        assert!(!root.path().join("alias.txt").exists());
        assert_eq!(
            std::fs::read(root.path().join("target.txt")).unwrap(),
            b"hello"
        );
    }
}

use std::fmt;
use std::io;

use nix::libc::EIO;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::fs_protocol::{
    FsDirEntry, FsMetadata, FsProxyError, FsProxyRequest, FsProxyResponse, FsStat,
    HOSTFS_PROTOCOL_VERSION, HelloRequest, HelloResponse, recv_msg, send_msg,
};

#[derive(Debug)]
pub enum HostFsClientError {
    Transport(anyhow::Error),
    Proxy(FsProxyError),
    UnexpectedResponse(&'static str),
}

impl HostFsClientError {
    pub fn errno(&self) -> i32 {
        match self {
            HostFsClientError::Proxy(err) => err.os_code.unwrap_or(EIO),
            HostFsClientError::Transport(err) => err
                .chain()
                .find_map(|cause| {
                    cause
                        .downcast_ref::<io::Error>()
                        .and_then(|io_err| io_err.raw_os_error())
                })
                .unwrap_or(EIO),
            HostFsClientError::UnexpectedResponse(_) => EIO,
        }
    }
}

impl fmt::Display for HostFsClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostFsClientError::Transport(err) => write!(f, "{err:#}"),
            HostFsClientError::Proxy(err) => write!(f, "{}", err.message),
            HostFsClientError::UnexpectedResponse(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for HostFsClientError {}

pub struct HostFsClient<S> {
    stream: S,
    hello: HelloResponse,
}

impl<S> HostFsClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub async fn connect(
        mut stream: S,
        mount_name: impl Into<String>,
    ) -> std::result::Result<Self, HostFsClientError> {
        let mount_name = mount_name.into();
        send_msg(
            &mut stream,
            &FsProxyRequest::Hello(HelloRequest {
                protocol_version: HOSTFS_PROTOCOL_VERSION,
                mount_name: mount_name.clone(),
            }),
        )
        .await
        .map_err(HostFsClientError::Transport)?;

        let response = recv_msg::<_, FsProxyResponse>(&mut stream)
            .await
            .map_err(HostFsClientError::Transport)?;

        let FsProxyResponse::Hello(hello) = decode_response(response)? else {
            return Err(HostFsClientError::UnexpectedResponse(
                "hostfs hello did not return a hello response",
            ));
        };

        if hello.mount_name != mount_name {
            return Err(HostFsClientError::UnexpectedResponse(
                "hostfs hello returned the wrong mount name",
            ));
        }
        if hello.protocol_version != HOSTFS_PROTOCOL_VERSION {
            return Err(HostFsClientError::UnexpectedResponse(
                "hostfs hello returned an unexpected protocol version",
            ));
        }

        Ok(Self { stream, hello })
    }

    pub fn read_only(&self) -> bool {
        self.hello.read_only
    }

    pub fn hello(&self) -> &HelloResponse {
        &self.hello
    }

    pub async fn ping(&mut self) -> std::result::Result<(), HostFsClientError> {
        match self.request(FsProxyRequest::Ping).await? {
            FsProxyResponse::Pong => Ok(()),
            _ => Err(HostFsClientError::UnexpectedResponse(
                "hostfs ping did not return pong",
            )),
        }
    }

    pub async fn statfs(&mut self) -> std::result::Result<FsStat, HostFsClientError> {
        match self.request(FsProxyRequest::StatFs).await? {
            FsProxyResponse::StatFs(stat) => Ok(stat),
            _ => Err(HostFsClientError::UnexpectedResponse(
                "hostfs statfs did not return filesystem stats",
            )),
        }
    }

    pub async fn metadata(
        &mut self,
        path: impl Into<String>,
    ) -> std::result::Result<FsMetadata, HostFsClientError> {
        match self
            .request(FsProxyRequest::GetMetadata { path: path.into() })
            .await?
        {
            FsProxyResponse::Metadata(metadata) => Ok(metadata),
            _ => Err(HostFsClientError::UnexpectedResponse(
                "hostfs metadata did not return entry metadata",
            )),
        }
    }

    pub async fn read_dir(
        &mut self,
        path: impl Into<String>,
    ) -> std::result::Result<Vec<FsDirEntry>, HostFsClientError> {
        match self
            .request(FsProxyRequest::ReadDir { path: path.into() })
            .await?
        {
            FsProxyResponse::ReadDir { entries } => Ok(entries),
            _ => Err(HostFsClientError::UnexpectedResponse(
                "hostfs readdir did not return directory entries",
            )),
        }
    }

    pub async fn read_file(
        &mut self,
        path: impl Into<String>,
        offset: u64,
        len: u32,
    ) -> std::result::Result<Vec<u8>, HostFsClientError> {
        match self
            .request(FsProxyRequest::ReadFile {
                path: path.into(),
                offset,
                len,
            })
            .await?
        {
            FsProxyResponse::ReadFile { data } => Ok(data),
            _ => Err(HostFsClientError::UnexpectedResponse(
                "hostfs read did not return file data",
            )),
        }
    }

    pub async fn write_file(
        &mut self,
        path: impl Into<String>,
        offset: u64,
        data: Vec<u8>,
        create: bool,
        truncate: bool,
    ) -> std::result::Result<u64, HostFsClientError> {
        match self
            .request(FsProxyRequest::WriteFile {
                path: path.into(),
                offset,
                data,
                create,
                truncate,
            })
            .await?
        {
            FsProxyResponse::WriteFile { written } => Ok(written),
            _ => Err(HostFsClientError::UnexpectedResponse(
                "hostfs write did not return a byte count",
            )),
        }
    }

    pub async fn set_len(
        &mut self,
        path: impl Into<String>,
        size: u64,
    ) -> std::result::Result<(), HostFsClientError> {
        expect_ok(
            self.request(FsProxyRequest::SetLen {
                path: path.into(),
                size,
            })
            .await?,
            "hostfs set_len did not return success",
        )
    }

    pub async fn mkdir(
        &mut self,
        path: impl Into<String>,
        recursive: bool,
    ) -> std::result::Result<(), HostFsClientError> {
        expect_ok(
            self.request(FsProxyRequest::Mkdir {
                path: path.into(),
                recursive,
            })
            .await?,
            "hostfs mkdir did not return success",
        )
    }

    pub async fn remove_file(
        &mut self,
        path: impl Into<String>,
    ) -> std::result::Result<(), HostFsClientError> {
        expect_ok(
            self.request(FsProxyRequest::RemoveFile { path: path.into() })
                .await?,
            "hostfs remove_file did not return success",
        )
    }

    pub async fn remove_dir(
        &mut self,
        path: impl Into<String>,
    ) -> std::result::Result<(), HostFsClientError> {
        expect_ok(
            self.request(FsProxyRequest::RemoveDir { path: path.into() })
                .await?,
            "hostfs remove_dir did not return success",
        )
    }

    pub async fn rename(
        &mut self,
        from: impl Into<String>,
        to: impl Into<String>,
    ) -> std::result::Result<(), HostFsClientError> {
        expect_ok(
            self.request(FsProxyRequest::Rename {
                from: from.into(),
                to: to.into(),
            })
            .await?,
            "hostfs rename did not return success",
        )
    }

    pub async fn fsync(
        &mut self,
        path: impl Into<String>,
    ) -> std::result::Result<(), HostFsClientError> {
        expect_ok(
            self.request(FsProxyRequest::Fsync { path: path.into() })
                .await?,
            "hostfs fsync did not return success",
        )
    }

    async fn request(
        &mut self,
        request: FsProxyRequest,
    ) -> std::result::Result<FsProxyResponse, HostFsClientError> {
        send_msg(&mut self.stream, &request)
            .await
            .map_err(HostFsClientError::Transport)?;
        let response = recv_msg::<_, FsProxyResponse>(&mut self.stream)
            .await
            .map_err(HostFsClientError::Transport)?;
        decode_response(response)
    }
}

fn decode_response(
    response: FsProxyResponse,
) -> std::result::Result<FsProxyResponse, HostFsClientError> {
    match response {
        FsProxyResponse::Error(err) => Err(HostFsClientError::Proxy(err)),
        response => Ok(response),
    }
}

fn expect_ok(
    response: FsProxyResponse,
    unexpected_message: &'static str,
) -> std::result::Result<(), HostFsClientError> {
    match response {
        FsProxyResponse::Ok => Ok(()),
        _ => Err(HostFsClientError::UnexpectedResponse(unexpected_message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostfs_service::HostFsService;
    use tempfile::tempdir;

    async fn connect_client(read_only: bool) -> HostFsClient<tokio::io::DuplexStream> {
        let root = tempdir().unwrap();
        let service = HostFsService::new("appdata", root.path(), read_only).unwrap();
        let (client, server) = tokio::io::duplex(128 * 1024);
        tokio::spawn(async move {
            service.serve_conn(server).await.unwrap();
        });
        HostFsClient::connect(client, "appdata").await.unwrap()
    }

    #[tokio::test]
    async fn hello_reports_mount_mode() {
        let client = connect_client(true).await;
        assert!(client.read_only());
        assert_eq!(client.hello().mount_name, "appdata");
    }

    #[tokio::test]
    async fn write_read_and_truncate_round_trip() {
        let root = tempdir().unwrap();
        let service = HostFsService::new("appdata", root.path(), false).unwrap();
        let (client, server) = tokio::io::duplex(128 * 1024);
        tokio::spawn(async move {
            service.serve_conn(server).await.unwrap();
        });

        let mut client = HostFsClient::connect(client, "appdata").await.unwrap();
        client.mkdir("data", true).await.unwrap();
        assert_eq!(
            client
                .write_file("data/test.txt", 0, b"abcdef".to_vec(), true, true)
                .await
                .unwrap(),
            6
        );
        assert_eq!(
            client.read_file("data/test.txt", 0, 16).await.unwrap(),
            b"abcdef"
        );
        client.set_len("data/test.txt", 3).await.unwrap();
        assert_eq!(
            client.read_file("data/test.txt", 0, 16).await.unwrap(),
            b"abc"
        );
    }

    #[tokio::test]
    async fn proxy_errors_preserve_errno() {
        let mut client = connect_client(true).await;
        let err = client
            .write_file("blocked.txt", 0, b"x".to_vec(), true, true)
            .await
            .unwrap_err();
        assert_eq!(err.errno(), nix::libc::EROFS);
    }
}

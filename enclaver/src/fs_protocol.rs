use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const HOSTFS_PROTOCOL_VERSION: u32 = 1;
const MAX_MSG_LEN: usize = 8 * 1024 * 1024;

pub async fn send_msg<W, M>(writer: &mut W, message: &M) -> Result<()>
where
    W: AsyncWrite + Unpin + Send,
    M: Serialize + Sync,
{
    let payload = serde_json::to_vec(message)?;
    if payload.len() > MAX_MSG_LEN {
        return Err(anyhow!(
            "hostfs protocol message too large: {} bytes (max {})",
            payload.len(),
            MAX_MSG_LEN
        ));
    }

    let len = u32::try_from(payload.len()).map_err(|_| {
        anyhow!(
            "hostfs protocol message too large: {} bytes cannot fit in u32",
            payload.len()
        )
    })?;

    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn recv_msg<R, M>(reader: &mut R) -> Result<M>
where
    R: AsyncRead + Unpin + Send,
    M: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_MSG_LEN {
        return Err(anyhow!(
            "hostfs protocol message too large: {} bytes (max {})",
            len,
            MAX_MSG_LEN
        ));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelloRequest {
    pub protocol_version: u32,
    pub mount_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelloResponse {
    pub protocol_version: u32,
    pub mount_name: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsProxyError {
    pub os_code: Option<i32>,
    pub message: String,
}

impl FsProxyError {
    pub fn new(os_code: Option<i32>, message: impl Into<String>) -> Self {
        Self {
            os_code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FsEntryType {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsMetadata {
    pub entry_type: FsEntryType,
    pub len: u64,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsDirEntry {
    pub name: String,
    pub entry_type: FsEntryType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsStat {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FsProxyRequest {
    Hello(HelloRequest),
    Ping,
    StatFs,
    GetMetadata {
        path: String,
    },
    ReadDir {
        path: String,
    },
    ReadFile {
        path: String,
        offset: u64,
        len: u32,
    },
    WriteFile {
        path: String,
        offset: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        create: bool,
        truncate: bool,
    },
    SetLen {
        path: String,
        size: u64,
    },
    Mkdir {
        path: String,
        recursive: bool,
    },
    RemoveFile {
        path: String,
    },
    RemoveDir {
        path: String,
    },
    Rename {
        from: String,
        to: String,
    },
    Fsync {
        path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FsProxyResponse {
    Hello(HelloResponse),
    Pong,
    StatFs(FsStat),
    Metadata(FsMetadata),
    ReadDir {
        entries: Vec<FsDirEntry>,
    },
    ReadFile {
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    WriteFile {
        written: u64,
    },
    Ok,
    Error(FsProxyError),
}

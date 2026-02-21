use anyhow::Result;
use circbuf::CircBuf;
use futures::Stream;
use ignore_result::Ignore;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch::{Receiver, Sender};
use tokio::task::JoinHandle;
use tokio_pipe::{PipeRead, PipeWrite};
use tokio_vsock::VsockStream;

use crate::launcher::ExitStatus;

const APP_LOG_CAPACITY: usize = 128 * 1024;

struct LogCursor {
    pos: usize,
}

impl LogCursor {
    fn new() -> Self {
        Self { pos: 0usize }
    }
}

struct ByteLog {
    buffer: CircBuf,
    head: usize,
    watches: WatchSet,
}

impl ByteLog {
    fn new() -> Self {
        Self {
            buffer: CircBuf::with_capacity(APP_LOG_CAPACITY).unwrap(),
            head: 0usize,
            watches: WatchSet::new(),
        }
    }

    // returns the number of bytes it trimmed from the head
    fn append(&mut self, data: &[u8]) -> usize {
        use std::io::Write;

        let mut trim_cnt = 0usize;

        let avail = self.buffer.avail();
        if avail < data.len() {
            trim_cnt = data.len() - avail;
            self.buffer.advance_read(trim_cnt).ignore();
            self.head += trim_cnt;
        }
        assert!(self.buffer.avail() >= data.len());

        assert!(self.buffer.write(data).unwrap() == data.len());

        // notify the watchers that an append happened
        self.watches.notify();

        trim_cnt
    }

    fn read(&self, cursor: &mut LogCursor, mut buf: &mut [u8]) -> usize {
        let mut copied = 0usize;

        let mut offset = if cursor.pos < self.head {
            cursor.pos = self.head;
            0usize
        } else {
            cursor.pos - self.head
        };

        for mut data in self.buffer.get_bytes_upto_size(buf.len() + offset) {
            if offset < data.len() {
                data = &data[offset..];
                offset = 0;

                buf[..data.len()].copy_from_slice(data);
                buf = &mut buf[data.len()..];

                copied += data.len();
            } else {
                offset -= data.len();
            }
        }

        cursor.pos += copied;

        copied
    }

    fn watch(&mut self) -> Receiver<()> {
        self.watches.add()
    }

    #[cfg(test)]
    fn cap(&self) -> usize {
        self.buffer.cap()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buffer.len()
    }
}

struct LogWriter {
    w_pipe: PipeWrite,
}

struct LogServicer {
    r_pipe: PipeRead,
    log: Arc<Mutex<ByteLog>>,
}

#[derive(Clone)]
struct LogReader {
    log: Arc<Mutex<ByteLog>>,
}

fn new_app_log() -> Result<(LogWriter, LogServicer, LogReader)> {
    let (r, w) = tokio_pipe::pipe()?;

    let log = Arc::new(Mutex::new(ByteLog::new()));

    let lw = LogWriter { w_pipe: w };

    let ls = LogServicer {
        r_pipe: r,
        log: log.clone(),
    };

    let lr = LogReader { log };

    Ok((lw, ls, lr))
}

impl LogWriter {
    fn redirect_stdio(&self) -> Result<()> {
        nix::unistd::dup2(self.w_pipe.as_raw_fd(), std::io::stdout().as_raw_fd())?;
        nix::unistd::dup2(self.w_pipe.as_raw_fd(), std::io::stderr().as_raw_fd())?;

        Ok(())
    }

    #[cfg(test)]
    async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.w_pipe.write_all(data).await?;
        Ok(())
    }
}

impl LogServicer {
    // run in the background and pull data off of the pipe
    async fn run(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = self.r_pipe.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }

            self.log.lock().unwrap().append(&buf[..n]);
        }
    }
}

impl LogReader {
    fn read(&self, cursor: &mut LogCursor, buf: &mut [u8]) -> usize {
        self.log.lock().unwrap().read(cursor, buf)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.log.lock().unwrap().len()
    }

    async fn write_all<W: AsyncWrite + Unpin>(
        &self,
        cursor: &mut LogCursor,
        writer: &mut W,
    ) -> Result<()> {
        let mut buf = vec![0u8; 4096];
        loop {
            let nread = self.read(cursor, &mut buf);
            if nread == 0 {
                break;
            }
            writer.write_all(&buf[..nread]).await?;
        }

        Ok(())
    }

    async fn stream<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let mut cursor = LogCursor::new();
        let mut w = self.log.lock().unwrap().watch();
        loop {
            self.write_all(&mut cursor, writer).await?;

            // wait for new data
            // unwrap() since the sender never closes first
            w.changed().await.unwrap();
        }
    }
}

pub struct AppLog {
    servicer: LogServicer,
    reader: LogReader,
}

impl AppLog {
    pub fn with_stdio_redirect() -> Result<Self> {
        let (w, s, r) = new_app_log()?;
        w.redirect_stdio()?;

        Ok(Self {
            servicer: s,
            reader: r,
        })
    }

    // serve the log over vsock
    async fn serve_log(incoming: impl Stream<Item = VsockStream>, lr: LogReader) -> Result<()> {
        use futures::stream::StreamExt;

        let mut incoming = Box::pin(incoming);
        while let Some(mut sock) = incoming.next().await {
            // TODO: get rid of detached tasks
            let lr = lr.clone();
            tokio::task::spawn(async move {
                // if send fails, remote side probably hung up, no need to do anything.
                _ = lr.stream(&mut sock).await;
            });
        }

        Ok(())
    }

    // launch a task to service the pipe and serve the log over vsock
    pub fn start_serving(mut self, port: u32) -> JoinHandle<Result<()>> {
        match enclaver::vsock::serve(port) {
            Ok(incoming) => tokio::task::spawn(async move {
                tokio::try_join!(
                    self.servicer.run(),
                    AppLog::serve_log(incoming, self.reader)
                )?;
                Ok(())
            }),
            Err(e) => tokio::task::spawn(async move { Err(e) }),
        }
    }
}

enum EntrypointStatus {
    Running,
    Exited(ExitStatus),
    Fatal(String),
}

impl EntrypointStatus {
    fn as_json(&self) -> String {
        match self {
            Self::Running => "{ \"status\": \"running\" }\n".to_string(),
            Self::Exited(exit_status) => match exit_status {
                ExitStatus::Exited(code) => {
                    format!("{{ \"status\": \"exited\", \"code\": {code} }}\n")
                }
                ExitStatus::Signaled(sig) => {
                    format!("{{ \"status\": \"signaled\", \"signal\": \"{sig}\" }}\n")
                }
            },
            Self::Fatal(err) => format!("{{ \"status\": \"fatal\", \"error\": \"{err}\" }}\n"),
        }
    }
}

struct AppStatusInner {
    status: EntrypointStatus,
    watches: WatchSet,
}

impl AppStatusInner {
    fn new() -> Self {
        Self {
            status: EntrypointStatus::Running,
            watches: WatchSet::new(),
        }
    }

    fn exited(&mut self, status: ExitStatus) {
        self.status = EntrypointStatus::Exited(status);
        self.watches.notify();
    }

    fn fatal(&mut self, err: String) {
        self.status = EntrypointStatus::Fatal(err);
        self.watches.notify();
    }
}

#[derive(Clone)]
pub struct AppStatus {
    inner: Arc<Mutex<AppStatusInner>>,
}

impl AppStatus {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(AppStatusInner::new())),
        }
    }

    pub fn exited(&self, status: ExitStatus) {
        self.inner.lock().unwrap().exited(status);
    }

    pub fn fatal(&self, err: String) {
        self.inner.lock().unwrap().fatal(err);
    }

    pub fn start_serving(&self, port: u32) -> JoinHandle<Result<()>> {
        use futures::stream::StreamExt;

        match enclaver::vsock::serve(port) {
            Ok(incoming) => {
                let mut incoming = Box::pin(incoming);
                let app_status = self.clone();
                tokio::task::spawn(async move {
                    while let Some(sock) = incoming.next().await {
                        let app_status = app_status.clone();
                        tokio::task::spawn(async move {
                            app_status.stream(sock).await;
                        });
                    }
                    Ok(())
                })
            }
            Err(e) => tokio::task::spawn(async move { Err(e) }),
        }
    }

    async fn stream(&self, mut sock: VsockStream) {
        let mut w = self.inner.lock().unwrap().watches.add();

        loop {
            let json_str = self.inner.lock().unwrap().status.as_json();
            _ = sock.write_all(json_str.as_bytes()).await;

            // wait for new data
            // unwrap() since the sender never closes first
            w.changed().await.unwrap();
        }
    }
}

// Broadcast mechanism that something being watched has changed
struct WatchSet {
    watches: Vec<Sender<()>>,
}

impl WatchSet {
    fn new() -> Self {
        Self {
            watches: Vec::new(),
        }
    }

    fn add(&mut self) -> Receiver<()> {
        let (tx, rx) = tokio::sync::watch::channel(());
        self.watches.push(tx);
        rx
    }

    fn notify(&mut self) {
        // first, clean up any closed channels
        self.watches.retain(|s| !s.is_closed());

        // now notify
        for w in &self.watches {
            _ = w.send(())
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Result, anyhow};
    use assert2::assert;
    use enclaver::constants::STATUS_PORT;
    use json::{JsonValue, object};
    use nix::sys::signal::Signal;
    use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader, Lines};
    use tokio_vsock::VsockStream;

    use super::{ByteLog, LogCursor};
    use crate::launcher::ExitStatus;

    fn check_log(log: &ByteLog, mut expected: u8) {
        // check that the log contents monotonically increase
        let mut c = LogCursor::new();

        let mut buf = vec![0u8; 1024];

        loop {
            match log.read(&mut c, &mut buf) {
                0 => break,
                nread => {
                    for actual in &buf[..nread] {
                        assert!(*actual == expected);
                        expected = expected.wrapping_add(1u8);
                    }
                }
            }
        }
    }

    fn iota_u8(slice: &mut [u8], mut start: u8) -> u8 {
        for x in slice {
            *x = start;
            start = start.wrapping_add(1u8);
        }

        start
    }

    #[test]
    fn test_byte_log() {
        let mut log = ByteLog::new();

        // append by a bit upto the log capacity
        let mut logged = 0usize;
        let mut quanta = 5;
        let mut i = 0u8;
        while logged < log.cap() - quanta {
            let mut data = vec![0u8; quanta];
            i = iota_u8(&mut data, i);

            assert!(log.append(&data) == 0usize);
            quanta += 1;
            logged += data.len();

            check_log(&log, 0);
        }

        let mut expected = 0u8;

        // overflow the log so it starts to trim
        while logged < log.cap() * 3 {
            let mut data = vec![0u8; quanta];
            i = iota_u8(&mut data, i);

            let trimmed = log.append(&data);
            assert!(trimmed > 0);
            quanta += 1;

            expected = expected.wrapping_add(trimmed as u8);
            check_log(&log, expected);

            logged += data.len();
        }
    }

    #[tokio::test]
    async fn test_app_log() {
        use rand::RngCore;
        use std::time::Duration;

        let (mut w, mut s, r) = super::new_app_log().unwrap();

        let runner = tokio::spawn(async move {
            s.run().await.unwrap();
        });

        let mut expected = vec![0u8; super::APP_LOG_CAPACITY * 3];
        rand::thread_rng().fill_bytes(&mut expected);

        // write all in small chunks
        for chunk in expected.chunks(53) {
            w.write(chunk).await.unwrap();
        }

        tokio::time::sleep(Duration::from_secs(1)).await;

        runner.abort();
        assert!(runner.await.unwrap_err().is_cancelled());

        // read the tail
        let mut c = LogCursor::new();
        let mut actual: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 1024];
        loop {
            let nread = r.read(&mut c, &mut buf);
            if nread == 0 {
                break;
            }

            actual.extend_from_slice(&mut buf[..nread]);
        }

        assert!(actual.len() == r.len());

        let tail_pos = expected.len() - actual.len();
        assert!(actual == expected[tail_pos..]);
    }

    async fn read_json<R: AsyncBufRead + Unpin>(lines: &mut Lines<R>) -> Result<JsonValue> {
        let line = lines.next_line().await?.ok_or(anyhow!("unexpected EOF"))?;

        Ok(json::parse(&line)?)
    }

    async fn app_status_lines() -> Result<Lines<impl AsyncBufRead + Unpin>> {
        let sock = VsockStream::connect(enclaver::vsock::VMADDR_CID_HOST, STATUS_PORT).await?;
        // bug in VsockStream::connect: it can return Ok even if connect failed
        _ = sock.peer_addr()?;
        Ok(BufReader::new(sock).lines())
    }

    #[tokio::test]
    async fn test_app_status() {
        let app_status = super::AppStatus::new();
        let status_task = app_status.start_serving(STATUS_PORT);

        let mut client1 = app_status_lines().await.unwrap();
        let mut client2 = app_status_lines().await.unwrap();

        // Running
        let mut expected = object! { status: "running" };

        let mut status = read_json(&mut client1).await.unwrap();

        assert!(status == expected);

        status = read_json(&mut client2).await.unwrap();
        assert!(status == expected);

        // Exited
        app_status.exited(ExitStatus::Exited(2));
        expected = object! { status: "exited", code: 2 };

        status = read_json(&mut client1).await.unwrap();
        assert!(status == expected);

        status = read_json(&mut client2).await.unwrap();
        assert!(status == expected);

        // Signaled
        app_status.exited(ExitStatus::Signaled(Signal::SIGTERM));
        expected = object! { status: "signaled", signal: "SIGTERM" };

        status = read_json(&mut client1).await.unwrap();
        assert!(status == expected);

        status = read_json(&mut client2).await.unwrap();
        assert!(status == expected);

        status_task.abort();
        _ = status_task.await;
    }
}

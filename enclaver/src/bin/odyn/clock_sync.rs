use std::time::Duration;

use anyhow::{Result, anyhow};
use log::{error, info, warn};
use nix::libc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::task::JoinHandle;
use tokio_vsock::VsockStream;

use crate::config::Configuration;
use enclaver::constants::CLOCK_SYNC_PORT;
use enclaver::vsock::VMADDR_CID_HOST;

const INITIAL_SYNC_MAX_ATTEMPTS: usize = 10;
const INITIAL_SYNC_RETRY_DELAY: Duration = Duration::from_secs(2);
const CLOCK_SYNC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const CLOCK_SYNC_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Enclave-side clock synchronization service.
///
/// Periodically connects to the host time server via vsock, retrieves the
/// current host timestamps, estimates offset/RTT, sets the enclave system clock,
/// and logs the adjustment.
pub struct ClockSyncService {
    task: Option<JoinHandle<()>>,
}

impl ClockSyncService {
    pub fn start(config: &Configuration) -> Self {
        let Some(cs_config) = config.clock_sync_config() else {
            info!("Clock sync disabled in manifest");
            return Self { task: None };
        };

        let interval_secs = cs_config.interval_secs;
        info!("Starting clock sync service (interval: {}s)", interval_secs);

        // Do an initial sync immediately, then periodically
        let task = tokio::spawn(async move {
            // Initial sync with retries
            let mut retries = 0;
            loop {
                match sync_once().await {
                    Ok(()) => break,
                    Err(e) => {
                        retries += 1;
                        if retries >= INITIAL_SYNC_MAX_ATTEMPTS {
                            error!("Clock sync: failed initial sync after {retries} attempts: {e}");
                            break;
                        }
                        warn!(
                            "Clock sync: initial sync attempt {retries} failed: {e}, retrying..."
                        );
                        tokio::time::sleep(INITIAL_SYNC_RETRY_DELAY).await;
                    }
                }
            }

            // Periodic sync
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            interval.tick().await; // consume the immediate first tick
            loop {
                interval.tick().await;
                if let Err(e) = sync_once().await {
                    error!("Clock sync failed: {e}");
                }
            }
        });

        Self { task: Some(task) }
    }

    pub async fn stop(self) {
        if let Some(task) = self.task {
            task.abort();
            _ = task.await;
        }
    }
}

/// Perform a single clock synchronization: connect to host, get time, set clock.
async fn sync_once() -> Result<()> {
    let mut stream = tokio::time::timeout(
        CLOCK_SYNC_CONNECT_TIMEOUT,
        VsockStream::connect(VMADDR_CID_HOST, CLOCK_SYNC_PORT),
    )
    .await
    .map_err(|_| anyhow!("timed out connecting to host time server"))??;
    let client_transmit = get_current_time()?;

    // Send a request (single newline)
    let line = tokio::time::timeout(CLOCK_SYNC_RESPONSE_TIMEOUT, async {
        stream.write_all(b"time\n").await?;
        stream.flush().await?;

        // Read the response: a JSON line with host receive/transmit timestamps.
        let reader = BufReader::new(&mut stream);
        let mut lines = reader.lines();
        lines
            .next_line()
            .await?
            .ok_or_else(|| anyhow!("no response from host time server"))
    })
    .await
    .map_err(|_| anyhow!("timed out waiting for host time server response"))??;
    let client_receive = get_current_time()?;

    let response: TimeResponse = serde_json::from_str(&line)?;
    let server_receive =
        Timestamp::new(response.server_receive_secs, response.server_receive_nanos);
    let server_transmit = Timestamp::new(
        response.server_transmit_secs,
        response.server_transmit_nanos,
    );

    let t1 = client_transmit.as_nanos();
    let t2 = server_receive.as_nanos();
    let t3 = server_transmit.as_nanos();
    let t4 = client_receive.as_nanos();

    let offset_nanos = ((t2 - t1) + (t3 - t4)) / 2;
    let rtt_nanos = (t4 - t1) - (t3 - t2);
    let host_processing_nanos = t3 - t2;

    let now_before = get_current_time()?;
    let target_time = Timestamp::from_nanos(now_before.as_nanos() + offset_nanos);

    set_system_time(target_time)?;

    let now_after = get_current_time()?;

    info!(
        "Clock synced: current_time={}, delta={:+.3}ms, rtt={:.3}ms, host_processing={:.3}ms, host_receive={}, host_transmit={}",
        now_after,
        nanos_to_millis(offset_nanos),
        nanos_to_millis(rtt_nanos),
        nanos_to_millis(host_processing_nanos),
        server_receive,
        server_transmit,
    );

    Ok(())
}

#[derive(serde::Deserialize)]
struct TimeResponse {
    server_receive_secs: i64,
    server_receive_nanos: u32,
    server_transmit_secs: i64,
    server_transmit_nanos: u32,
}

#[derive(Clone, Copy, Debug)]
struct Timestamp {
    secs: i64,
    nanos: u32,
}

impl Timestamp {
    fn new(secs: i64, nanos: u32) -> Self {
        Self { secs, nanos }
    }

    fn as_nanos(self) -> i128 {
        (self.secs as i128 * 1_000_000_000) + self.nanos as i128
    }

    fn from_nanos(total_nanos: i128) -> Self {
        let secs = total_nanos.div_euclid(1_000_000_000);
        let nanos = total_nanos.rem_euclid(1_000_000_000) as u32;
        Self {
            secs: secs as i64,
            nanos,
        }
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:09}s", self.secs, self.nanos)
    }
}

fn nanos_to_millis(nanos: i128) -> f64 {
    nanos as f64 / 1_000_000.0
}

/// Get the current system time as seconds/nanoseconds since epoch.
fn get_current_time() -> Result<Timestamp> {
    let mut tv = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ret = unsafe {
        // SAFETY: We pass a valid pointer to a timespec struct.
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut tv)
    };
    if ret != 0 {
        anyhow::bail!("clock_gettime failed: {}", std::io::Error::last_os_error());
    }

    Ok(Timestamp::new(tv.tv_sec, tv.tv_nsec as u32))
}

/// Set the system clock to the given timestamp.
fn set_system_time(timestamp: Timestamp) -> Result<()> {
    let tv = libc::timespec {
        tv_sec: timestamp.secs as libc::time_t,
        tv_nsec: timestamp.nanos as libc::c_long,
    };
    let ret = unsafe {
        // SAFETY: We pass a valid pointer to a properly initialized timespec struct.
        libc::clock_settime(libc::CLOCK_REALTIME, &tv)
    };
    if ret != 0 {
        anyhow::bail!("clock_settime failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

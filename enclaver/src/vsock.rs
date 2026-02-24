use anyhow::Result;
use futures::{Stream, StreamExt};
use log::{debug, error, info};
use tokio_vsock::{VsockListener, VsockStream};

pub const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
pub const VMADDR_CID_LOCAL: u32 = 1;
pub const VMADDR_CID_HOST: u32 = 2;

// Listen on a vsock with the given port.
// Returns a Stream of connected sockets.
pub fn serve(port: u32) -> Result<impl Stream<Item = VsockStream> + Unpin> {
    let listener = VsockListener::bind(VMADDR_CID_ANY, port)?;

    info!("Listening on vsock port {port}");
    let stream = listener.incoming().filter_map(move |result| {
        futures::future::ready(match result {
            Ok(vsock) => {
                debug!("Connection accepted on port {port}");
                Some(vsock)
            }

            Err(err) => {
                error!("Failed to accept a vsock: {err}");
                None
            }
        })
    });

    Ok(stream)
}

// Listen on a vsock, automatically finding an available port starting from the given port.
// If the requested port is in use, tries port+1, port+2, etc., up to max_attempts.
// Returns a Stream of connected sockets and the actual port bound.
pub fn serve_auto(
    preferred_port: u32,
    max_attempts: u32,
) -> Result<(impl Stream<Item = VsockStream> + Unpin, u32)> {
    let mut last_error = None;

    for attempt in 0..max_attempts {
        let port = preferred_port + attempt;

        match VsockListener::bind(VMADDR_CID_ANY, port) {
            Ok(listener) => {
                if attempt > 0 {
                    info!("Port {preferred_port} was in use, bound to vsock port {port} instead");
                } else {
                    info!("Listening on vsock port {port}");
                }

                let stream = listener.incoming().filter_map(move |result| {
                    futures::future::ready(match result {
                        Ok(vsock) => {
                            debug!("Connection accepted on port {port}");
                            Some(vsock)
                        }
                        Err(err) => {
                            error!("Failed to accept a vsock: {err}");
                            None
                        }
                    })
                });

                return Ok((stream, port));
            }
            Err(err) => {
                // Check if this is an "address in use" error
                if err.kind() == std::io::ErrorKind::AddrInUse {
                    debug!("Port {port} is in use, trying next port");
                    last_error = Some(err);
                    continue;
                } else {
                    // For other errors, fail immediately
                    return Err(err.into());
                }
            }
        }
    }

    // If we exhausted all attempts, return the last error
    Err(last_error.unwrap().into())
}

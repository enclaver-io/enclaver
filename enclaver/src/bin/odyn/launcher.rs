use anyhow::{anyhow, Result};
use log::debug;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use tokio::task::JoinHandle;

pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
}

pub enum ExitStatus {
    Exited(i32),
    Signaled(Signal),
}

impl std::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            ExitStatus::Exited(code) => write!(f, "exited with {}", code),
            ExitStatus::Signaled(sig) => write!(f, "terminated by {}", sig),
        }
    }
}

// runs the child and reaps all of its children as well
pub fn run_child(
    argv: &[OsString],
    creds: &Credentials,
    work_dir: Option<PathBuf>,
) -> Result<ExitStatus> {
    // Don't use tokio::process::Command because it wants to reap the process.
    // However we need to run waitpid() ourselves to reap the zombies and it'll
    // end up picking up the spawned child as well.
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .uid(creds.uid)
        .gid(creds.gid)
        .process_group(0);

    if let Some(dir) = work_dir {
        cmd.current_dir(dir);
    }

    let child = cmd.spawn()?;

    debug!("Child process started");
    let child_pid = Pid::from_raw(child.id() as i32);

    reap(child_pid)
}

// runs the child and reaps all of its children as well
pub fn start_child(
    argv: Vec<OsString>,
    creds: Credentials,
    work_dir: Option<PathBuf>,
) -> JoinHandle<Result<ExitStatus>> {
    tokio::task::spawn_blocking(move || run_child(&argv, &creds, work_dir))
}

// Reap processes until a process with sentinel pid exits.
// Returns the exit status for the sentinel process
fn reap(sentinel: Pid) -> Result<ExitStatus> {
    let flags = WaitPidFlag::empty();

    loop {
        let wait_status = nix::sys::wait::waitpid(None, Some(flags))
            .map_err(|e| anyhow!("waitpid failed: {}", e))?;

        match wait_status {
            WaitStatus::Exited(pid, status) => {
                debug!("Zombie with PID {} reaped", pid);
                if pid == sentinel {
                    // our child is done, exit
                    return Ok(ExitStatus::Exited(status));
                }
            }
            WaitStatus::Signaled(pid, sig, _) => {
                debug!("Zombie with PID {} reaped", pid);
                if pid == sentinel {
                    // our child crashed by signal, exit
                    return Ok(ExitStatus::Signaled(sig));
                }
            }
            _ => {}
        }
    }
}

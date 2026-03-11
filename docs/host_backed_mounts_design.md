# Host-Backed Persistent Mounts

This document describes the current Enclaver design and implementation for
host-backed persistent directories inside Nitro Enclaves.

## Goal

- let an enclave application use a normal directory such as `/mnt/appdata`
- persist that directory on the parent instance
- keep the application interface language-agnostic

## Architecture

The runtime path is:

```text
host state dir
  -> fixed-size loopback image
  -> host mountpoint on the parent instance
  -> Docker bind mount into the Sleeve container
  -> hostfs proxy in enclaver-run
  -> vsock request/response protocol
  -> FUSE mount in odyn
  -> mount path inside the enclave
  -> application uses normal file APIs
```

The loopback image is the quota boundary for each mount. When the image fills,
filesystem operations fail with `ENOSPC`.

## Runtime Flow

1. The manifest declares `storage.mounts[]`.
2. `enclaver run --mount <name>=<host_state_dir>` resolves the runtime bindings.
3. The host-side wrapper creates or reuses `HOST_STATE_DIR/.enclaver-hostfs/disk.img`,
   formats it, mounts it on the parent instance, and bind-mounts it into the
   Sleeve container.
4. `enclaver-run` starts one hostfs proxy per mount on deterministic vsock ports.
5. `odyn` creates the target mount directories, ensures `/dev/fuse` exists, and
   mounts a FUSE filesystem at each configured `mount_path`.
6. The application starts only after required mounts are ready.

## Manifest Shape

```yaml
storage:
  mounts:
    - name: appdata
      mount_path: /mnt/appdata
      required: true
      size_mb: 10240
```

Runtime example:

```bash
enclaver run -f enclaver.yaml --mount appdata=/var/lib/my-service/appdata
```

## Protocol

The hostfs protocol is a framed JSON protocol over vsock. Each request opens a
fresh vsock connection, performs a `hello` handshake, sends one filesystem
operation, receives one response, and closes the connection.

Current operations:

- `hello`
- `ping`
- `statfs`
- `get_metadata`
- `read_dir`
- `read_file`
- `write_file`
- `set_len`
- `mkdir`
- `remove_file`
- `remove_dir`
- `rename`
- `fsync`

This keeps the transport simple and avoids long-lived shared state between FUSE
threads and the host proxy.

## Security Model

This storage is persistent, but it is not trusted.

- the parent instance still controls the backing storage
- the parent instance can tamper with the stored bytes
- the parent instance can observe file sizes, names, and access timing
- the enclave must not treat mounted content as trusted code or trusted config

Use application-level encryption, integrity checks, or signatures if the data
must be trusted after it leaves enclave memory.

## Filesystem Semantics

The current implementation provides normal directory and file operations for the
common application path:

- create/open/read/write/truncate
- mkdir/readdir
- unlink/rmdir
- rename
- fsync/statfs

Symlink and xattr management are not implemented as first-class operations.
Existing symlinks are surfaced in metadata and directory listings, but explicit
`readlink`, `symlink`, and xattr operations still return `ENOSYS`.

## Key Files

- `enclaver/src/manifest.rs`
- `enclaver/src/hostfs.rs`
- `enclaver/src/fs_protocol.rs`
- `enclaver/src/hostfs_service.rs`
- `enclaver/src/hostfs_client.rs`
- `enclaver/src/proxy/fs_host.rs`
- `enclaver/src/run.rs`
- `enclaver/src/bin/odyn/fs_mount.rs`
- `enclaver/src/bin/odyn/main.rs`

## Operational Notes

- each mount gets its own loopback image and quota
- optional mounts are skipped if the matching runtime bind is absent
- required mounts fail startup if the runtime bind or host proxy is unavailable
- host-side prerequisites are `mkfs.ext4`, `mount`, and `umount`
- Linux validation on a Nitro-capable host can be exercised with `scripts/hostfs-smoke-test.sh`

# Enclaver CLI Reference

The `enclaver` command-line tool is the primary interface for building and running secure applications in Nitro Enclaves.

## Usage

```bash
enclaver [OPTIONS] <COMMAND>
```

## Global Options

| Option | Description |
|--------|-------------|
| `-v`, `--verbose` | Increase logging verbosity (can be used multiple times). |
| `-h`, `--help` | Print help information. |
| `-V`, `--version` | Print version information. |

---

## Commands

### `build`

Packages a Docker image into a self-executing Enclaver container image.

#### Options

| Option | Description |
|--------|-------------|
| `-f`, `--file <PATH>` | Path to the Enclaver manifest file (`enclaver.yaml`). Defaults to `enclaver.yaml` in the current directory. Pass `-` to read from stdin. |
| `--pull` | Always pull the source Docker images to ensure the latest versions are used. |

#### Example
```bash
enclaver build -f my-service.yaml
```

---

### `run`

Runs a pre-packaged Enclaver container image. This command simplifies the `docker run` process by automatically handling device mapping and privileged mode requirements.

#### Options

| Option | Description |
|--------|-------------|
| `-f`, `--file <PATH>` | Enclaver manifest file. If provided, `enclaver` will look up the `target` image name from this file. |
| `image` (positional) | Name of a pre-existing Enclaver image to run. Only used if `-f` is not specified. |
| `-p`, `--publish <PORT_MAP>` | Port to expose on the host machine (e.g., `8080:80`). Can be used multiple times. |
| `-d`, `--debug-mode` | Enable debug mode for the enclave supervisor. |
| `--cpu-count <INT>` | **(New)** Number of vCPUs to assign to the enclave. Overrides the `defaults` section in `enclaver.yaml`. |
| `--memory-mb <INT>` | **(New)** Enclave memory in MiB. Overrides the `defaults` section in `enclaver.yaml`. |

#### Parameter Priority (CPU/RAM)

When using `enclaver run`, the resource allocation is determined by:
1. **Command-line flags** (`--cpu-count`, `--memory-mb`) - **Highest priority**.
2. **Manifest defaults** (the `defaults` section in `enclaver.yaml`).
3. **Hardcoded defaults** (CPU: 2, Memory: 4096 MiB).

#### Examples

**Run using manifest lookup:**
```bash
sudo enclaver run -f enclaver.yaml
```

**Run specific image with overrides:**
```bash
sudo enclaver run my-service:latest --cpu-count 4 --memory-mb 8192
```

**Publishing ports:**
```bash
sudo enclaver run my-service:latest -p 8080:80 -p 9000:9000
```

---

## Notes

- **Privileges**: Running enclaves requires `sudo` or root permissions to access `/dev/nitro_enclaves`.
- **Docker Dependency**: `enclaver run` requires a running Docker daemon.

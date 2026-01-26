## CI and Release workflows

This document explains the two GitHub Actions workflows in this repository:
- `.github/workflows/ci.yaml` (CI)
- `.github/workflows/release.yaml` (Release / Build Release)

It describes triggers, jobs, important steps, permissions, how to reproduce key steps locally, and suggestions for improvements.

---

## 1. CI (`.github/workflows/ci.yaml`)

### Trigger
- Runs on `push` and `pull_request` events.

### Concurrency and environment
- Concurrency: grouped by `${{ github.workflow }}-${{ github.ref }}` with `cancel-in-progress: true` to avoid redundant runs.
- Global env variables:
  - `CARGO_REGISTRIES_CRATES_IO_PROTOCOL: "sparse"` — use sparse protocol for crates.io
  - `RUSTFLAGS: "-Dwarnings"` — treat warnings as errors

### Job: `clippy-check`
- Runner: `ubuntu-latest`
- Key steps:
  1. Checkout the repository (`actions/checkout@v4`).
  2. Parse MSRV from `enclaver/Cargo.toml` and set `RUSTUP_TOOLCHAIN`.
  3. Install the toolchain (`rustup toolchain install $RUSTUP_TOOLCHAIN`).
  4. Install Clippy and Rustfmt (`rustup component add clippy rustfmt`).
  5. Run `cargo clippy --no-deps --manifest-path enclaver/Cargo.toml` (default features).
  6. Run clippy again with `--features=run_enclave,odyn` to check all binaries.
  7. Run clippy with tracing enabled (`RUSTFLAGS="--cfg=tokio_unstable"`) and the `tracing` feature.

### Purpose
- Static analysis gate: enforces Clippy lints and fails on any warnings (because warnings are denied).

### Local reproduction
Run the equivalent steps locally to match CI behavior:

```bash
# install matching toolchain (example: 1.86)
rustup toolchain install 1.86
rustup component add clippy rustfmt

# default feature check
cargo clippy --no-deps --manifest-path enclaver/Cargo.toml

# check all binaries
cargo clippy --no-deps --manifest-path enclaver/Cargo.toml --features=run_enclave,odyn

# check with tracing enabled
RUSTFLAGS="--cfg=tokio_unstable" \
  cargo clippy --no-deps --manifest-path enclaver/Cargo.toml --features=run_enclave,odyn,tracing
```

Tip: set `RUSTFLAGS="-Dwarnings"` locally to match the CI strictness.

---

## 2. Release (`.github/workflows/release.yaml`)

### Trigger
- Runs on `push` to `main` and on pushes of tags matching `v*` (used for releases).

### Concurrency and permissions
- Concurrency: same grouping strategy as CI.
- Requires extra permissions: `id-token: write`, `attestations: write` for SLSA provenance and OIDC-based AWS auth.

### Jobs overview
There are three main responsibilities in this workflow:
1. `build-release-binaries` — build release binaries for multiple platforms.
2. `publish-images` — build and push multi-arch Docker images (only runs for the official repo and main/tag refs).
3. `upload-release-artifact` — package and upload release artifacts to GitHub Releases (only for tags).

### `build-release-binaries` details
- Uses a matrix that includes:
  - `x86_64-unknown-linux-musl` (Ubuntu, musl)
  - `aarch64-unknown-linux-musl` (Ubuntu, musl)
- Steps:
  - Install the target toolchain (`actions-rs/toolchain@v1`).
  - Use `Swatinem/rust-cache@v2` to cache `target` artifacts per target.
  - For musl targets: use the repo's `./.github/actions/cargo-zigbuild` (a wrapper around `cargo-zigbuild`) to produce static musl binaries.
  - Generate SLSA provenance and upload the built binaries as artifacts: `enclaver`, `enclaver-run`, `odyn`.

### `publish-images` details
- Runs only when `github.repository == 'enclaver-io/enclaver'` and on main/tag refs.
- Steps:
  - Download artifacts produced by the build job.
  - Re-arrange directories so architecture-specific binaries match Dockerfile expectations (rename `x86_64-unknown-linux-musl` → `amd64`, `aarch64-unknown-linux-musl` → `arm64`).
  - Set up Docker Buildx and authenticate to AWS (assume a role using `aws-actions/configure-aws-credentials@v5`).
  - Use `docker/metadata-action` to generate tags, then `docker/build-push-action` to build & push multi-arch images (odyn and runtime base).
  - Generate and push SLSA provenance for images.

### `upload-release-artifact` details
- Runs on tag pushes (and only for the official repo). For each target it:
  - Downloads artifacts, packages them into a platform-specific tar.gz, computes a SHA256, and uploads them to a GitHub Release (as a draft) using `softprops/action-gh-release`.

### Local reproduction notes

Building musl targets locally:

```bash
# install cargo-zigbuild and zig
cargo install cargo-zigbuild
# build musl binary
cargo zigbuild --release --target x86_64-unknown-linux-musl --manifest-path enclaver/Cargo.toml --features="run_enclave,odyn"
```

Building images locally (example):

```bash
# prepare directories amd64/ and arm64/ containing the built binaries
docker buildx build --platform linux/amd64,linux/arm64 \
  --file dockerfiles/odyn-release.dockerfile \
  --build-context artifacts=. \
  --push \
  -t public.ecr.aws/your-repo/odyn:localtest .
```

Note: CI authenticates to AWS ECR by assuming a hard-coded role. To push to ECR locally you need equivalent AWS credentials or use an alternate registry for testing.

---

## Key differences (CI vs Release)

- Purpose:
  - CI: static analysis and linting (Clippy).
  - Release: building cross-platform release binaries, producing provenance, pushing multi-arch images, and publishing release artifacts.
- Trigger:
  - CI: push/PR
  - Release: push to main or tag
- Permissions:
  - Release requires more permissions (OIDC/AWS, attestations) than CI.

---

## Suggestions

- Add a `tests` job to CI that runs `cargo test` (or split fast/slow tests) to catch runtime regressions earlier.
- Make `publish-images` registry/role configurable via workflow inputs or secrets so contributors can test image builds against alternative registries.
- Monitor transitive dependency future-compat warnings (e.g., `num-bigint-dig`) and consider automated dependency updates.

---

## AWS Infrastructure Setup

The release workflow requires AWS resources for OIDC authentication and ECR access. These are defined in the CloudFormation template at `aws/cloudformation/infrastructure.yml`.

### Required Resources

| Resource | Purpose |
|----------|---------|
| **GitHubOIDCProvider** | Enables GitHub Actions to authenticate with AWS using OIDC (no long-lived credentials) |
| **GitHubActionsECRRole** | IAM Role assumed by GitHub Actions to push images to ECR Public |

### Deployment

Deploy the CloudFormation stack in **us-east-1** (required for ECR Public):

```bash
aws cloudformation deploy \
  --stack-name enclaver-ci \
  --template-file aws/cloudformation/infrastructure.yml \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

### ECR Public Repositories

After deploying the stack, manually create the following ECR Public repositories in the AWS Console under the `sparsity-ai` namespace:

- `sparsity-ai/odyn`
- `sparsity-ai/sleeve`
- `sparsity-ai/nitro-cli`

### Workflow Configuration

The workflows reference the IAM role by ARN:

```yaml
# In .github/workflows/release.yaml
- name: Configure AWS credentials from OIDC
  uses: aws-actions/configure-aws-credentials@v5
  with:
    aws-region: us-east-1
    role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/Github-Workflow-Publish-AWS-ECR
```

The role ARN is output by the CloudFormation stack as `GitHubActionsRoleArn`.

---

## References / locations

- CI workflow: `.github/workflows/ci.yaml`
- Release workflow: `.github/workflows/release.yaml`
- AWS infrastructure: `aws/cloudformation/infrastructure.yml`
- Local image build helper: `scripts/build-docker-images.sh`
- Custom action used in Release: `./.github/actions/cargo-zigbuild`

If you'd like, I can add a `tests` job draft to `ci.yaml` or add a `workflow_dispatch` input to `release.yaml` for manual runs. Let me know which you prefer.


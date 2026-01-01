# Enclaver Base Images

This document summarizes the base images used by Enclaver, what they contain (as inferred from this repository), and commands you can run locally to inspect them.

Date: 2025-10-27

Overview
--------
Enclaver uses three primary base images in its build and runtime flow. The repository references these images as defaults when a manifest doesn't override them. The images are published under the public ECR hostname used in this project.

- Nitro CLI image (default): `public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest`
- ODYN image (supervisor): `public.ecr.aws/d4t4u8d2/sparsity-ai/odyn:latest`
- Sleeve image: `public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest`

Where these are referenced in the repository
-----------------------------------------
- `enclaver/src/build.rs` contains the defaults used by `EnclaveArtifactBuilder`:

```rust
  const NITRO_CLI_IMAGE: &str = "public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest";
  const ODYN_IMAGE: &str = "public.ecr.aws/d4t4u8d2/sparsity-ai/odyn:latest";
  const SLEEVE_IMAGE: &str = "public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest";
```

- The multi-stage Dockerfile `dockerfiles/sleeve-release.dockerfile` uses the `nitro-cli` image as a build source and copies runtime libraries and `/usr/bin/nitro-cli` from it into the runtime image. If you need to rebuild nitro-cli from source, use the provided [nitro-cli.dockerfile](file:///home/ubuntu/enclaver/dockerfiles/nitro-cli.dockerfile) and [build-and-publish-nitro-cli.sh](file:///home/ubuntu/enclaver/scripts/build-and-publish-nitro-cli.sh).

- The dev helper `scripts/build-docker-images.sh` builds local dev images `odyn-dev:latest` and `sleeve:latest` for local development.

What each image is for (summary)
--------------------------------

1. Nitro CLI image (`nitro-cli`)
   - Purpose: Provides the `nitro-cli` binary and the system libraries required to run it.
   - In the build pipeline the repo runs `nitro-cli build-enclave` inside a container based on this image to convert a Docker image into an EIF.
  - In the runtime Dockerfile (`sleeve-release.dockerfile`) the image is used as a source stage to extract runtime libraries and the `nitro-cli` executable into the final container image.

2. ODYN image (`odyn`)
   - Purpose: Contains the `odyn` supervisor binary (the supervisor that is inserted into the amended app image and executed inside the enclave).
   - `build::amend_source_image` copies the supervisor binary from this image into the amended app image at `/sbin/odyn`.
   - Dev Dockerfile `odyn-dev.dockerfile` is a minimal image that simply copies a built local `odyn` binary into `/usr/local/bin/odyn` (development flow).

3. Sleeve image (`sleeve`)
   - Purpose: The release base image which receives the `application.eif` and `enclaver.yaml` files as appended layers. The runtime entrypoint (`enclaver-run`) lives in this image and orchestrates enclave start/stop when the sleeve container runs.
   - The final release image layout is: base sleeve image + layer with `RELEASE_BUNDLE_DIR/enclaver.yaml` + layer with `RELEASE_BUNDLE_DIR/application.eif`.

Notes derived from repository files
----------------------------------
- `sleeve-release.dockerfile` copies the following from the `nitro-cli` image into the runtime:
  - runtime libraries such as `libssl.so.3`, `libcrypto.so.3`, `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`, `libz.so.1`
  - the `nitro-cli` binary into `/bin/nitro-cli`
  - it also ensures certain paths exist for Nitro Enclaves (`/var/log/nitro_enclaves/`, `/run/nitro_enclaves/`).

- `build.rs` uses the `odyn` image to read a binary (`ODYN_IMAGE_BINARY_PATH = "/usr/local/bin/odyn"`) and copy it into the amended app image.

Building/Rebuilding Nitro CLI image
-----------------------------------
While Enclaver defaults to the upstream `enclaver-io/nitro-cli` image, this repository provides the necessary tools to build and publish a compatible version to the `sparsity-ai` registry if needed.

- **Dockerfile**: [nitro-cli.dockerfile](file:///home/ubuntu/enclaver/dockerfiles/nitro-cli.dockerfile)
- **Build Script**: [build-and-publish-nitro-cli.sh](file:///home/ubuntu/enclaver/scripts/build-and-publish-nitro-cli.sh)

To build and push a custom version:
```bash
./scripts/build-and-publish-nitro-cli.sh --tag latest
```
After pushing, you should update the `NITRO_CLI_IMAGE` constant in `enclaver/src/build.rs` if you wish to use the new image by default.

What the repository does not provide
-----------------------------------
- Historically, the repo did not include the full Dockerfiles for the published `enclaver-io` images. We have now added a fallback Dockerfile for `nitro-cli`, but the `nitro-cli` binaries and kernel blobs are still sourced from official AWS repositories via `dnf install`.

Commands to inspect the images locally
-------------------------------------
Use these commands to pull and inspect the published images locally. Replace `<image>` with one of the three image names above.

1) Pull the image

```bash
docker pull public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest || true
docker pull public.ecr.aws/d4t4u8d2/sparsity-ai/odyn:latest || true
docker pull public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest || true
```

2) Inspect image metadata and config

```bash
docker image inspect public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest --format '{{json .}}' | jq .
```

3) View layer history

```bash
docker history public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest
```

4) Run a short `ls` in the image (non-interactive)

```bash
docker run --rm --entrypoint ls public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest -la /usr/bin /lib64 || true
```

5) Start an interactive shell (if the image has one) to explore filesystem

```bash
docker run --rm -it --entrypoint /bin/sh public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest
```

6) Inspect the final sleeve image / release image after you build it locally

```bash
# after running `enclaver build` which tags the release image as e.g. my-release:latest
docker inspect my-release:latest
docker history my-release:latest
docker run --rm --entrypoint ls my-release:latest -la /enclave
```

7) Use `dive` to examine layers interactively (recommended)

```bash
dive public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest
```

Inspecting the EIF conversion step
---------------------------------
- The repo uses a container (based on the `nitro-cli` image) and runs `nitro-cli build-enclave --docker-uri <tag> --output-file application.eif` inside the container to create the EIF. Because `nitro-cli` insists on pulling by name rather than using a local image id, the build process tags the intermediate amended image with a temporary random tag and calls `nitro-cli` with that tag.

Dev / local images
-------------------
`scripts/build-docker-images.sh` builds local dev images to avoid pulling the remote published images during development. It builds multi-arch crate binaries (via cargo cross-compile target selection) and then builds two dev images:
  - `odyn-dev:latest`
  - `sleeve:latest` (local sleeve base tag)

Helper: a simple inspection script (optional)
-------------------------------------------
If you want a quick helper, here is a small one-liner you can save as `scripts/inspect-base-images.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
images=(
  public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest
  public.ecr.aws/d4t4u8d2/sparsity-ai/odyn:latest
  public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest
)

for img in "${images[@]}"; do
  echo "\n=== $img ==="
  docker pull "$img" || true
  docker image inspect "$img" --format 'ID: {{.Id}}\nRepoTags: {{.RepoTags}}\nSize: {{.Size}}' || true
  echo "history:";
  docker history --no-trunc "$img" | sed -n '1,10p'
done
```

Save it and run:

```bash
chmod +x scripts/inspect-base-images.sh
./scripts/inspect-base-images.sh
```

If you want me to add that helper script into the repository, I can create it for you.

Next steps I can take
---------------------
- Add the helper script above into `scripts/` in this repo.
- Pull and inspect the images for you and paste the `docker inspect` and `docker history` summaries here (I will not run Docker commands on your machine; I can provide the exact commands for you to run and parse the output if you prefer).

---
File generated from repository analysis on 2025-10-27.

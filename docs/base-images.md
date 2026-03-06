# Enclaver Base Images

Enclaver uses three important images in its build and runtime flow. The defaults live in `enclaver/src/build.rs`:

- Nitro CLI: `public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest`
- Odyn: `public.ecr.aws/d4t4u8d2/sparsity-ai/odyn:latest`
- Sleeve: `public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest`

## What each image does

### Nitro CLI image

Purpose:

- provides `nitro-cli`
- provides the runtime libraries copied into sleeve images
- is used as the build environment for `nitro-cli build-enclave`

Relevant files:

- `dockerfiles/sleeve-release.dockerfile`
- `dockerfiles/sleeve-dev.dockerfile`
- `dockerfiles/nitro-cli.dockerfile`
- `scripts/build-and-publish-nitro-cli.sh`

The release workflow does not publish a `nitro-cli` image from this repository. Enclaver consumes the default public image unless you override the build sources or rebuild a compatible replacement.

### Odyn image

Purpose:

- supplies the `odyn` supervisor binary at `/usr/local/bin/odyn`
- is read at build time, then copied into the amended app image as `/sbin/odyn`

Relevant files:

- `enclaver/src/build.rs`
- `dockerfiles/odyn-dev.dockerfile`
- `dockerfiles/odyn-release.dockerfile`

Local tags used by repository tooling:

- debug helper build: `odyn-dev:latest`
- release-style local build: `odyn:latest`

### Sleeve image

Purpose:

- provides the host-side runtime container entrypoint `enclaver-run`
- provides `nitro-cli` and its runtime libraries
- receives `/enclave/application.eif` and `/enclave/enclaver.yaml` as appended layers during `enclaver build`

Relevant files:

- `dockerfiles/sleeve-dev.dockerfile`
- `dockerfiles/sleeve-release.dockerfile`
- `enclaver/src/build.rs`
- `enclaver/src/run_container.rs`

Local tags used by repository tooling:

- debug helper build: `sleeve-dev:latest`
- release-style local build: `sleeve:latest`

## How the images are used

Build time:

1. resolve the app image
2. read the Odyn binary from the Odyn image
3. amend the app image with:
   - `/etc/enclaver/enclaver.yaml`
   - `/sbin/odyn`
4. run `nitro-cli build-enclave` inside the Nitro CLI image to produce `application.eif`
5. append `application.eif` and `enclaver.yaml` to the Sleeve image

Runtime:

- the final release image is a Sleeve image plus `/enclave/application.eif` and `/enclave/enclaver.yaml`
- `enclaver-run` starts inside the container and uses `nitro-cli` to launch the enclave

## Local inspection commands

```bash
docker pull public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest
docker pull public.ecr.aws/d4t4u8d2/sparsity-ai/odyn:latest
docker pull public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest

docker image inspect public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest
docker history public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest

docker run --rm --entrypoint ls \
  public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest \
  -la /usr/bin /lib64
```

After building a release image locally:

```bash
docker inspect my-release:latest
docker history my-release:latest
docker run --rm --entrypoint ls my-release:latest -la /enclave
```

## Related files

- `enclaver/src/build.rs`
- `dockerfiles/nitro-cli.dockerfile`
- `dockerfiles/odyn-dev.dockerfile`
- `dockerfiles/odyn-release.dockerfile`
- `dockerfiles/sleeve-dev.dockerfile`
- `dockerfiles/sleeve-release.dockerfile`
- `scripts/build-docker-images.sh`
- `scripts/build-and-publish-nitro-cli.sh`

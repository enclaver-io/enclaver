# hn-fetcher — example HTTP forwarder

This is a minimal example app that forwards an HTTP GET to an upstream host (news.ycombinator.com) and returns the upstream response.

## Build app image and run

Build the app image with:

```bash
docker build -t hn-fetcher .
```

Verify the app image with:

```bash
docker images hn-fetcher
```

You should see output like:
```bash
$ docker images hn-fetcher
REPOSITORY   TAG       IMAGE ID       CREATED         SIZE
hn-fetcher   latest    ee0c1f4cab82   8 minutes ago   182MB
```

You can run the app image directly with:

```bash
docker run --rm -p 8000:8000 hn-fetcher
curl http://localhost:8000
```

## Build the enclaver image

The content of `enclaver.yaml` is:

```yaml
version: v1
name: "hn-fetcher"
target: "hn-fetcher-enclave:latest"
sources:
  app: "hn-fetcher:latest"
  #odyn: "odyn-dev:latest"
  #sleeve: "sleeve:latest"
defaults:
  memory_mb: 1500
ingress:
  - listen_port: 8000
egress:
  allow:
    - news.ycombinator.com
api:
  listen_port: 9000
aux_api:
  listen_port: 9001
```

The manifest includes:
- `ingress` - Allows external HTTP traffic on port 8000
- `egress` - Allows outbound requests to news.ycombinator.com
- `api` - Enables the internal API service on port 9000 (provides attestation and key management)
- `aux_api` - Enables the auxiliary API on port 9001 (provides controlled external access to select API endpoints)

Then build enclaver image with command:

```bash
enclaver build -f enclaver.yaml
```

You should be able to see output like:

```bash
$ enclaver build -f enclaver.yaml
 INFO  enclaver::build > using app image: sha256:ee0c1f4cab82262ffbd05e413b36048cf2c387d0b596d63a554c1cebcaa3fde4
 INFO  enclaver::build > using nitro-cli image: sha256:14dd347aec286f67025c824762876b0226d0a890033bcd4ac5076c06fe90eee8
 INFO  enclaver::build > built intermediate image: sha256:92e215dfbf655667138269800c78b13da7eb776e2ecf4013a4dd2812ef5547ea
 INFO  enclaver::build > started nitro-cli build-eif in container: 483f1b333cf023f72324fb9357d3b5934d83fa9e434927b2cf67b3f2be01bb7d
 INFO  nitro-cli::build-eif > Start building the Enclave Image...
 INFO  nitro-cli::build-eif > Using the locally available Docker image...
 INFO  nitro-cli::build-eif > Enclave Image successfully created.
 INFO  enclaver::build      > packaging EIF into release image
{
  "Sources": {
    "App": {
      "ID": "sha256:ee0c1f4cab82262ffbd05e413b36048cf2c387d0b596d63a554c1cebcaa3fde4"
    },
    "Odyn": {
      "ID": "sha256:f575f2d220ca03a451a86bc6f21931f51129e5af5116adfc74c16c1390fe5269",
      "Name": "public.ecr.aws/d4t4u8d2/sparsity-ai/odyn:latest",
      "RepoDigest": "public.ecr.aws/d4t4u8d2/sparsity-ai/odyn@sha256:e7a3d42461cde57b5203f305911314ec1ca0c8c04d6fa854a2881c67b6bcdba4"
    },
    "NitroCLI": {
      "ID": "sha256:14dd347aec286f67025c824762876b0226d0a890033bcd4ac5076c06fe90eee8",
      "Name": "public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest",
      "RepoDigest": "public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli@sha256:83d1bf977d62d68fe49763c94fb0d1ab23dc59a5844e9f5b86a07ccf7618ced9"
    },
    "Sleeve": {
      "ID": "sha256:1545dc67f60a477e737b1cf2c563717f5c27ffb356a906fa6bf77936f34bf5b2",
      "Name": "public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve:latest",
      "RepoDigest": "public.ecr.aws/d4t4u8d2/sparsity-ai/sleeve@sha256:d0114166eb5d885ad2bb449a1811aa2e32233e51322548676533890559b8e803"
    }
  },
  "Measurements": {
    "PCR0": "be7f3bfa8c460b9840f7440d4c834e42d209e1c780db9a3b63acef1a10c85cf2b6ce5d95cb34c796cf5e7f79f5fd8b5d",
    "PCR1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
    "PCR2": "c810e8d6dbf7800b6099b13a4fa30f661c04ff2e66fddaa8b6a10df5f549b9d3275e43381aaec8dc5ff26c0148545415"
  },
  "Image": {
    "ID": "sha256:f9969846514bdc67e3f6e24ac81e842a045c6ed71547b44f44d432c5cc77691c",
    "Name": "hn-fetcher-enclave:latest"
  }
}
```

Verify the enclave image with:

```bash
docker images hn-fetcher-enclave
```
You should see output like:

```bash
$ docker images hn-fetcher-enclave
REPOSITORY           TAG       IMAGE ID       CREATED         SIZE
hn-fetcher-enclave   latest    99259a94f49d   2 minutes ago   237MB
```

## Run enclaver image

Run the enclave image with:
```bash
enclaver run --publish 8000:8000 --publish 9001:9001 hn-fetcher-enclave:latest
```

Test the application:
```bash
curl http://localhost:8000
```

## Using the Auxiliary API

The auxiliary API provides controlled external access to enclave functionality. It proxies requests to the internal API while sanitizing inputs to prevent external callers from overriding security-critical defaults.

### Available Endpoints

#### Get Ethereum Address

Retrieve the enclave's Ethereum address derived from the enclave's keypair:

```bash
curl http://localhost:9001/v1/eth/address
```

Example response:
```json
{
  "address": "0x1234567890abcdef1234567890abcdef12345678"
}
```

#### Request Attestation

Request an attestation document from the enclave. You can optionally provide a nonce for freshness:

```bash
# Request attestation with default parameters
curl -X POST http://localhost:9001/v1/attestation \
  -H "Content-Type: application/json" \
  -d '{}'

# Request attestation with a custom nonce
curl -X POST http://localhost:9001/v1/attestation \
  -H "Content-Type: application/json" \
  -d '{"nonce": "your-base64-encoded-nonce-here"}'
```

Example response:
```json
{
  "attestation_document": "base64-encoded-attestation-document",
  "public_key": "base64-encoded-public-key"
}
```

**Security Note:** The aux API automatically sanitizes incoming requests by removing `public_key` and `user_data` fields to prevent external callers from overriding the enclave's internal defaults. This ensures that the attestation document always contains the enclave's authentic keypair and metadata.

## Check aws nitro enclave info

You can check the nitro enclave info with:
```bash
[ec2-user@ip-10-0-10-174 enclaver]$ docker ps
CONTAINER ID   IMAGE                       COMMAND                  CREATED          STATUS          PORTS                                       NAMES
b6a4c7cee8b1   hn-fetcher-enclave:latest   "/usr/local/bin/encl…"   12 minutes ago   Up 12 minutes   0.0.0.0:8000->8000/tcp, :::8000->8000/tcp   silly_curran
[ec2-user@ip-10-0-10-174 enclaver]$ docker exec -it <docker_id> /bin/nitro-cli describe-enclaves
[
  {
    "EnclaveName": "application",
    "EnclaveID": "i-0210c9c07d1985549-enc19a56927412da47",
    "ProcessID": 13,
    "EnclaveCID": 18,
    "NumberOfCPUs": 2,
    "CPUIDs": [
      1,
      3
    ],
    "MemoryMiB": 1500,
    "State": "RUNNING",
    "Flags": "NONE",
    "Measurements": {
      "HashAlgorithm": "Sha384 { ... }",
      "PCR0": "be7f3bfa8c460b9840f7440d4c834e42d209e1c780db9a3b63acef1a10c85cf2b6ce5d95cb34c796cf5e7f79f5fd8b5d",
      "PCR1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
      "PCR2": "c810e8d6dbf7800b6099b13a4fa30f661c04ff2e66fddaa8b6a10df5f549b9d3275e43381aaec8dc5ff26c0148545415"
    }
  }
]
```
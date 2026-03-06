# Internal API Mock Service

This repository does not implement a local mock `odyn` server.

What exists here is:

- the real Internal API implemented in `enclaver/src/api.rs`
- the real Aux API implemented in `enclaver/src/aux_api.rs`
- example client code in external Nova example repositories

## External mock endpoints

Some example apps use an external endpoint such as:

```text
http://odyn.sparsity.cloud:18000
```

That endpoint is not part of this repository and is not versioned together with Enclaver. Treat it as an external development convenience, not as a guaranteed mirror of the current `odyn` implementation.

## Recommended usage pattern

If you want your app to switch between enclave-local and external development endpoints, use an app-level environment variable:

```python
import os

IN_ENCLAVE = os.getenv("IN_ENCLAVE", "false").lower() == "true"
ODYN_BASE_URL = "http://127.0.0.1:18000" if IN_ENCLAVE else "http://odyn.sparsity.cloud:18000"
```

Notes:

- `IN_ENCLAVE` is not set automatically by Enclaver
- choose and manage that convention in your own application image or deployment environment
- if your manifest uses a different `api.listen_port`, update the enclave-local URL accordingly

## Compatibility expectations

When using an external mock service, do not assume:

- every endpoint from `docs/internal_api.md` exists
- response bodies exactly match the current repository implementation
- KMS, app-wallet, S3, or attestation behavior is fully faithful
- error codes and edge cases match current `odyn`

The authoritative contract for this repository is the implementation plus:

- `docs/internal_api.md`
- `docs/encryption.md`
- `docs/odyn.md`

## Recommendation

Use the external mock only for lightweight application development loops. Before relying on a behavior, verify it against the real enclave runtime or the actual code in this repository.

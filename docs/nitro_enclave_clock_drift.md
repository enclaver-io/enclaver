# Clock Drift in AWS Nitro Enclaves

## Overview

AWS Nitro Enclaves provide a highly isolated execution environment
designed for sensitive workloads such as key management, cryptography,
and confidential computing.

However, one operational characteristic developers should be aware of is
**clock drift inside the enclave**.

Because of the strict isolation model, **Nitro Enclaves do not
automatically synchronize their system clock with the host after
startup**. As a result, the enclave's time may gradually diverge from
the parent instance's time.

This document explains:

-   Why clock drift occurs
-   Known reports from the community
-   Potential risks
-   Recommended mitigation strategies

------------------------------------------------------------------------

# Nitro Enclave Time Model

Nitro Enclaves are intentionally designed with minimal external
dependencies.

Key isolation properties include:

-   No network access
-   No direct access to host OS
-   Communication only through **vsock**
-   Limited device access

Because of these restrictions, the enclave **cannot use NTP or other
time synchronization services**.

### Time initialization

When an enclave starts, it receives an **initial snapshot of the host
system time**.

    enclave_time = host_time_at_start + local_clock_drift

After startup:

-   The enclave clock **runs independently**
-   It **does not automatically synchronize with the host**

Over time, this leads to **clock drift**.

------------------------------------------------------------------------

# Observed Clock Drift

Clock drift in Nitro Enclaves has been observed in real production
environments.

For example, Evervault documented this issue while building
enclave-based infrastructure.

Their findings indicated:

-   Approximately **7 seconds of drift per week**

While this drift is relatively small, it can cause problems for systems
that rely on accurate wall-clock time.

Example affected systems:

-   JWT token validation
-   TLS certificate verification
-   cryptographic signature expiration
-   time-based authentication

------------------------------------------------------------------------

# Why Nitro Enclaves Do Not Provide Trusted Wall Clock

This behavior is not unique to Nitro Enclaves. Most Trusted Execution
Environments (TEEs) **do not provide a trusted wall clock**.

  TEE              Trusted Wall Clock
  ---------------- --------------------
  SGX              No
  TDX              No
  SEV-SNP          No
  Nitro Enclaves   No

The reason is that **time is external state**.

If the host or infrastructure provider is malicious, time could be
manipulated.

Because of this, TEE security models typically assume:

> Wall clock time is not trustworthy.

Instead, protocols rely on:

-   monotonic counters
-   nonces
-   expiration windows
-   cryptographic freshness guarantees

------------------------------------------------------------------------

# Attestation Timestamp Limitations

Nitro Enclave attestation documents contain a `timestamp` field.

Example fields in an attestation document:

-   PCR measurements
-   nonce
-   enclave public key
-   timestamp

However:

-   This timestamp reflects the time **when the attestation document was
    generated**
-   It should **not be treated as a globally trusted time source**

It is mainly used together with **nonces or short validity windows** to
prevent replay attacks.

------------------------------------------------------------------------

# Practical Issues Caused by Clock Drift

Clock drift may lead to failures in several common scenarios.

### JWT Validation

JWT tokens typically contain:

    exp
    nbf
    iat

If enclave time drifts, validation may fail with errors like:

    token not yet valid
    token expired

------------------------------------------------------------------------

### TLS Certificate Validation

If TLS verification is performed inside the enclave, certificate checks
may fail:

    certificate not yet valid
    certificate expired

------------------------------------------------------------------------

### Cryptographic Protocols

Some protocols depend on timestamp-based freshness checks.

Clock drift may cause:

-   signature validation failures
-   authentication errors
-   protocol timeouts

------------------------------------------------------------------------

# Recommended Time Synchronization Approaches

There are several strategies to mitigate clock drift.

## 1. Synchronize Time via Host (Common Approach)

The most common approach is to synchronize enclave time with the host
via **vsock**.

Architecture:

    Amazon Time Sync Service (host)
              │
              │
           Parent Instance
              │
              │ vsock
              ▼
           Nitro Enclave
           Time Sync Agent

Example workflow:

    loop every 30 seconds:
        request host_time via vsock
        update enclave clock

This approach is simple and widely used in production deployments.

------------------------------------------------------------------------

## 2. Use the PTP Device

Nitro instances expose a **Precision Time Protocol (PTP) device**:

    /dev/ptp0

Developers can run time synchronization services such as:

-   chrony
-   PTP client implementations

Benefits:

-   microsecond-level synchronization
-   recommended by AWS for high-precision timing

Limitations:

-   requires additional configuration

------------------------------------------------------------------------

## 3. Use Monotonic Time Only

If the application does not require wall-clock time, it may be better to
rely on **monotonic time**.

Example use cases:

-   measuring elapsed time
-   retry timeouts
-   protocol sequencing

Monotonic clocks avoid many problems caused by time manipulation or
drift.

------------------------------------------------------------------------

# Enclave Restart Behavior

Another important characteristic:

When an enclave starts or restarts, its time is reinitialized from the
host.

    start enclave
         │
         ▼
    enclave_time = host_time_snapshot

Therefore:

  Enclave Lifetime        Drift Impact
  ----------------------- -------------------
  Short-lived enclaves    Minimal
  Long-running enclaves   Drift accumulates

Many production systems restart enclaves periodically to avoid long-term
drift.

------------------------------------------------------------------------

# Summary

Nitro Enclave clock behavior can be summarized as follows.

  Property                    Behavior
  --------------------------- ----------------------
  Independent clock           Yes
  Automatic synchronization   No
  Clock drift possible        Yes
  Typical observed drift      \~7 seconds per week
  Recommended mitigation      Host sync or PTP

Developers building enclave-based systems should explicitly account for
time synchronization when designing their infrastructure.

------------------------------------------------------------------------

# Key Takeaways

-   Nitro Enclaves **do not automatically synchronize system time**
-   Clock drift is **expected behavior**
-   Drift has been observed in real production deployments
-   Applications relying on accurate time must implement synchronization
    mechanisms
-   Trusted wall clocks are generally **not available in TEEs**

Proper time handling is essential when building secure systems on
confidential computing platforms.

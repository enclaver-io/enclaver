# HTTP(S) Proxy Support Guidance for Enclave Applications

## Scope & Assumptions

- Applications run **inside an enclave** (e.g., SGX / TDX / Nitro Enclaves)
- No direct outbound network access is available
- All external HTTP/HTTPS traffic **must go through a proxy**
- Proxy configuration is provided via environment variables:
  - `HTTP_PROXY`
  - `HTTPS_PROXY`
  - `NO_PROXY`

Any HTTP client that **ignores proxy environment variables is unusable by default** in this environment.

---

## Executive Summary

**Do NOT assume proxy support.**

Many modern, standardized HTTP client APIs intentionally **ignore `HTTP_PROXY` / `HTTPS_PROXY`** for reasons of security and predictability.

> If proxy support is not explicitly documented or configured, assume it is **NOT supported**.

---

## Proxy Support Matrix (Default Behavior)

Legend:
- ✅ Supported by default
- ❌ Not supported
- ⚠️ Supported only with explicit configuration

---

## Node.js

| Client / API | Proxy Env Support | Notes |
|-------------|------------------|------|
| `fetch` (Node 18+, undici) | ❌ | Does not read proxy env vars |
| `http.request` / `https.request` | ❌ | Low-level API, no env support |
| `axios` | ⚠️ | Requires `proxy-from-env` |
| `node-fetch` | ❌ | Deprecated |
| `undici` + `ProxyAgent` | ⚠️ | Must configure explicitly |

**Guidance**
- ❌ Do **not** use `fetch` inside enclaves
- ✅ Use `undici` with `ProxyAgent`, or `axios + proxy-from-env`

---

## Go

| Client / API | Proxy Env Support | Notes |
|-------------|------------------|------|
| `http.DefaultClient` | ✅ | Uses `ProxyFromEnvironment` |
| Custom `http.Client` with custom `Transport` | ❌ | Proxy support lost unless re-added |

**Common Pitfall**
```go
&http.Transport{} // breaks proxy support
```

**Correct Configuration**
```go
Transport: &http.Transport{
    Proxy: http.ProxyFromEnvironment,
}
```

**Guidance**
- ✅ Prefer `http.DefaultClient`
- ⚠️ Explicitly set `ProxyFromEnvironment` when customizing transports

---

## Python

| Client / API | Proxy Env Support | Notes |
|-------------|------------------|------|
| `requests` | ✅ | Fully supports proxy env vars |
| `urllib.request` | ⚠️ | Requires `ProxyHandler` |
| `http.client` | ❌ | No env support |

**Guidance**
- ✅ Use `requests`
- ❌ Avoid `http.client`

---

## Java

| Client / API | Proxy Env Support | Notes |
|-------------|------------------|------|
| `HttpURLConnection` | ⚠️ | Requires JVM system properties |
| `HttpClient` (Java 11+) | ❌ | Does not read proxy env vars |

**Guidance**
- ❌ Do not rely on env vars with Java 11+ `HttpClient`
- ⚠️ Always configure proxy explicitly via `ProxySelector` or JVM flags

---

## Rust

| Client / API | Proxy Env Support | Notes |
|-------------|------------------|------|
| `reqwest` | ⚠️ | Requires proxy-related features |
| `hyper` | ❌ | No proxy env support |

**Guidance**
- ⚠️ Enable proxy features explicitly in `reqwest`
- ❌ Avoid `hyper` for enclave networking

---

## .NET

| Client / API | Proxy Env Support | Notes |
|-------------|------------------|------|
| `HttpClient` | ⚠️ | Depends on handler & platform |

**Guidance**
- Explicit proxy configuration strongly recommended
- Do not assume environment variables are honored

---

## C / C++

| Client / API | Proxy Env Support | Notes |
|-------------|------------------|------|
| `libcurl` | ✅ | Industry standard |
| Raw sockets | ❌ | No support |

**Guidance**
- ✅ Prefer `libcurl` whenever possible

---

## PHP

| Client / API | Proxy Env Support | Notes |
|-------------|------------------|------|
| `file_get_contents` | ❌ | No env support |
| `curl` extension | ✅ | Full support |

---

## Recommended Libraries for Enclave Environments

### Strongly Recommended
- **libcurl (C/C++)**
- **Python `requests`**
- **Go `net/http` (default client)**
- **Node.js `undici` + `ProxyAgent`**

### Explicitly Discouraged
- Node.js `fetch`
- Java 11+ `HttpClient` (without manual proxy configuration)
- Rust `hyper`
- Python `http.client`

---

## Enclave-Specific Best Practices

1. **Fail fast**: verify proxy connectivity at startup
2. **Make proxy usage explicit**: avoid hidden defaults
3. **Document proxy requirements** as mandatory runtime dependencies
4. **Log effective proxy configuration** (redact credentials)
5. **Avoid implicit behavior** that may change across runtime versions

---

## Recommended Startup Self-Test

```bash
curl https://ifconfig.me
```

Or a controlled internal endpoint reachable only via the proxy.

---

## Final Guidance Statement

> Any HTTP client used inside an enclave **MUST** either explicitly support
> `HTTP_PROXY` / `HTTPS_PROXY`, or be configured programmatically to route all
> traffic through a proxy.
>
> Clients that silently ignore proxy environment variables **MUST NOT be used**.


# Enclaver Runtime Architecture

This document provides a comprehensive overview of the Enclaver runtime architecture, explaining the relationships between all components and their responsibilities during both build-time and runtime phases.

---

## Table of Contents

1. [Component Overview](#component-overview)
2. [Build-Time Architecture](#build-time-architecture)
3. [Runtime Architecture](#runtime-architecture)
4. [What's Inside vs Outside the EIF](#whats-inside-vs-outside-the-eif)
5. [Module Relationships](#module-relationships)
6. [Data Flow Diagrams](#data-flow-diagrams)

---

## Component Overview

### High-Level Component Diagram

```mermaid
graph TB
    subgraph "User Space"
        APP["User Application<br/>(Docker Image)"]
        YAML["enclaver.yaml<br/>(Configuration)"]
    end
    
    subgraph "Build-Time Components"
        ENCLAVER_CLI["enclaver CLI<br/>(build command)"]
        ODYN_IMAGE["Odyn Image<br/>(supervisor binary)"]
        NITRO_CLI_BUILD["nitro-cli<br/>(build-enclave)"]
        SLEEVE_BASE["Sleeve Base Image"]
    end
    
    subgraph "Docker Image (Release)"
        SLEEVE["Sleeve Program<br/>(enclaver-run)"]
        NITRO_CLI_RUN["nitro-cli<br/>(run-enclave)"]
        EIF["application.eif<br/>(Enclave Image File)"]
        YAML_COPY["enclaver.yaml"]
    end
    
    subgraph "Enclave (Inside EIF)"
        ODYN["Odyn Supervisor<br/>(/sbin/odyn)"]
        APP_INSIDE["User Application"]
    end
    
    APP --> ENCLAVER_CLI
    YAML --> ENCLAVER_CLI
    ODYN_IMAGE --> ENCLAVER_CLI
    ENCLAVER_CLI --> NITRO_CLI_BUILD
    NITRO_CLI_BUILD --> EIF
    SLEEVE_BASE --> SLEEVE
    EIF --> SLEEVE
    YAML --> SLEEVE
    SLEEVE --> NITRO_CLI_RUN
    NITRO_CLI_RUN --> ODYN
    ODYN --> APP_INSIDE
```

### Component Descriptions

| Component | Location | Description |
|-----------|----------|-------------|
| **User Application** | User's Docker image | Your backend service/application to be run inside the enclave |
| **enclaver.yaml** | User's project | Configuration file defining ingress, egress, API, and KMS proxy settings |
| **Odyn Supervisor** | Inside EIF | Enclave supervisor that manages the application lifecycle, networking, and services |
| **EIF (application.eif)** | Docker image | AWS Nitro Enclave Image File containing the enclave workload |
| **Sleeve (enclaver-run)** | Docker image | Host-side orchestrator that launches and manages the enclave |
| **nitro-cli** | Docker image / Build | AWS CLI tool for building and running Nitro Enclaves |
| **Docker Image** | Container registry | Final packaged image containing all runtime components |

---

## Build-Time Architecture

### Build Pipeline Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI as enclaver CLI
    participant Docker as Docker Engine
    participant NitroCLI as nitro-cli Container
    
    User->>CLI: enclaver build -f enclaver.yaml
    CLI->>CLI: Load manifest (enclaver.yaml)
    CLI->>Docker: Pull user's app image
    CLI->>Docker: Amend app image<br/>(add odyn + manifest)
    Note over Docker: Creates intermediate image with:<br/>- /sbin/odyn (supervisor)<br/>- /etc/enclaver/enclaver.yaml
    CLI->>NitroCLI: Run nitro-cli build-enclave
    NitroCLI->>NitroCLI: Convert amended image to EIF
    NitroCLI-->>CLI: Return application.eif
    CLI->>Docker: Package EIF into sleeve base
    Note over Docker: Final release image contains:<br/>- /enclave/application.eif<br/>- /enclave/enclaver.yaml<br/>- /usr/local/bin/enclaver-run<br/>- /bin/nitro-cli
    CLI-->>User: Tagged release image ready
```

### Layer Structure of Release Image

```
┌─────────────────────────────────────────────────────────────┐
│                    Release Docker Image                     │
├─────────────────────────────────────────────────────────────┤
│  [Layer 3] /enclave/application.eif (EIF file)              │
├─────────────────────────────────────────────────────────────┤
│  [Layer 2] /enclave/enclaver.yaml (manifest)                │
├─────────────────────────────────────────────────────────────┤
│  [Layer 1] Sleeve Base Image                                │
│    ├── /usr/local/bin/enclaver-run (entry point)            │
│    ├── /bin/nitro-cli (AWS Nitro CLI)                       │
│    └── Runtime libraries and dependencies                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Runtime Architecture

### Runtime Execution Flow

```mermaid
sequenceDiagram
    participant Host
    participant Container as Docker Container
    participant Sleeve as enclaver-run (Sleeve)
    participant NitroCLI as nitro-cli
    participant Enclave as Enclave VM
    participant Odyn as Odyn Supervisor
    participant App as User Application
    
    Host->>Container: docker run <release-image>
    Container->>Sleeve: Start enclaver-run
    Sleeve->>Sleeve: Load /enclave/enclaver.yaml
    Sleeve->>Sleeve: Start host-side egress proxy
    Sleeve->>NitroCLI: nitro-cli run-enclave<br/>--eif /enclave/application.eif
    NitroCLI->>Enclave: Launch enclave VM
    Enclave->>Odyn: Start /sbin/odyn
    
    Note over Odyn: Bootstrap Phase
    Odyn->>Odyn: Bring up loopback interface
    Odyn->>Odyn: Seed RNG from NSM
    Odyn->>Odyn: Start egress proxy (if configured)
    Odyn->>Odyn: Start KMS proxy (if configured)
    Odyn->>Odyn: Start API server (if configured)
    Odyn->>Odyn: Start ingress proxies
    Odyn->>App: Launch user application
    
    Note over Sleeve,Odyn: Runtime Communication (vsock)
    Odyn-->>Sleeve: App logs via vsock (port 17001)
    Odyn-->>Sleeve: Status updates via vsock (port 17000)
    Sleeve->>Sleeve: Start host-side ingress proxies
    
    Note over Host,App: Application Running
    App-->>Odyn: Exit status
    Odyn-->>Sleeve: Final exit status
    Sleeve->>NitroCLI: nitro-cli terminate-enclave
    Sleeve-->>Host: Container exits
```

### Component Responsibilities at Runtime

#### Sleeve (enclaver-run) - Host Side
- **Location**: Runs inside the Docker container, outside the enclave
- **Responsibilities**:
  - Read configuration from `/enclave/enclaver.yaml`
  - Start host-side egress proxy (forwards enclave traffic to external networks)
  - Launch the enclave using `nitro-cli run-enclave`
  - Start host-side ingress proxies (listen on TCP ports, forward to enclave via vsock)
  - Monitor enclave status and logs via vsock connections
  - Handle enclave lifecycle (start, monitor, terminate)

#### Odyn Supervisor - Enclave Side
- **Location**: Runs inside the enclave (as PID 1)
- **Responsibilities**:
  - Bootstrap enclave platform (loopback interface, RNG seeding from NSM)
  - Parse and apply configuration from embedded `enclaver.yaml`
  - Start enclave-side ingress proxies (accept vsock connections, forward to app)
  - Start enclave-side egress proxy (intercept app's outbound traffic)
  - Start KMS proxy (handle AWS KMS requests with attestation)
  - Start internal API server (attestation, encryption, Ethereum endpoints)
  - Start Helios RPC service (trustless Ethereum/OP Stack light client)
  - Launch and supervise the user application
  - Capture app stdout/stderr and expose via vsock
  - Report application status to host via vsock

---

## What's Inside vs Outside the EIF

### Inside the EIF (Enclave)

```
┌────────────────────────────────────────────────────────┐
│               Enclave (application.eif)                │
├────────────────────────────────────────────────────────┤
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │           Odyn Supervisor (/sbin/odyn)           │  │
│  │                                                  │  │
│  │  ┌────────────────────────────────────────────┐  │  │
│  │  │ Services:                                  │  │  │
│  │  │  • Ingress Proxy (vsock → app TCP)         │  │  │
│  │  │  • Egress Proxy (app HTTP → vsock)         │  │  │
│  │  │  • KMS Proxy (AWS KMS with attestation)    │  │  │
│  │  │  • API Server (attestation, encryption)    │  │  │
│  │  │  • Helios RPC (trustless Ethereum/OP Stack light client)  │  │  │
│  │  │  • Console (log capture & streaming)       │  │  │
│  │  │  • Launcher (app process management)       │  │  │
│  │  └────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────┘  │
│                          │                             │
│                          ▼                             │
│  ┌──────────────────────────────────────────────────┐  │
│  │             User Application                     │  │
│  │       (from original Docker image)               │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  Configuration: /etc/enclaver/enclaver.yaml            │
│                                                        │
└────────────────────────────────────────────────────────┘
```

**Components Inside EIF:**
- Odyn supervisor binary (`/sbin/odyn`)
- User application (original Docker image contents)
- Configuration file (`/etc/enclaver/enclaver.yaml`)
- All application dependencies and runtime

### Outside the EIF (Host/Container)

```
┌────────────────────────────────────────────────────────┐
│              Docker Container (Host Side)              │
├────────────────────────────────────────────────────────┤
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │         Sleeve (enclaver-run)                    │  │
│  │                                                  │  │
│  │  ┌────────────────────────────────────────────┐  │  │
│  │  │ Host-Side Proxies:                         │  │  │
│  │  │  • Ingress HostProxy (TCP → vsock)         │  │  │
│  │  │  • Egress HostHttpProxy (vsock → network)  │  │  │
│  │  └────────────────────────────────────────────┘  │  │
│  │                                                  │  │
│  │  ┌────────────────────────────────────────────┐  │  │
│  │  │ Enclave Management:                        │  │  │
│  │  │  • Log streaming (vsock port 17001)        │  │  │
│  │  │  • Status monitoring (vsock port 17000)    │  │  │
│  │  │  • Debug console (optional)                │  │  │
│  │  └────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │              nitro-cli                           │  │
│  │  • run-enclave (start enclave from EIF)          │  │
│  │  • describe-enclaves (query status)              │  │
│  │  • terminate-enclave (stop enclave)              │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  Files:                                                │
│    /enclave/application.eif                            │
│    /enclave/enclaver.yaml                              │
│                                                        │
│  Device:                                               │
│    /dev/nitro_enclaves (mounted from host)             │
│                                                        │
└────────────────────────────────────────────────────────┘
```

**Components Outside EIF:**
- Sleeve program (`enclaver-run`)
- nitro-cli binary
- EIF file (`application.eif`)
- Configuration file (`enclaver.yaml`)
- Host-side proxy processes
- Device access (`/dev/nitro_enclaves`)

### Summary Table

| Component | Inside EIF | Outside EIF |
|-----------|:----------:|:-----------:|
| User Application | ✓ | |
| Odyn Supervisor | ✓ | |
| enclaver.yaml (copy) | ✓ | ✓ |
| Sleeve (enclaver-run) | | ✓ |
| nitro-cli | | ✓ |
| application.eif | | ✓ |
| Helios RPC Service | ✓ | |
| Host-side Proxies | | ✓ |
| Enclave-side Proxies | ✓ | |

---

## Module Relationships

### Ingress Traffic Flow

```mermaid
graph LR
    subgraph "External"
        CLIENT["External Client"]
    end
    
    subgraph "Docker Container (Host)"
        HOST_INGRESS["HostProxy<br/>(TCP Listener)"]
    end
    
    subgraph "Enclave"
        ENCLAVE_INGRESS["EnclaveProxy<br/>(vsock → TCP)"]
        APP["User Application"]
    end
    
    CLIENT -->|"TCP/HTTPS"| HOST_INGRESS
    HOST_INGRESS -->|"vsock"| ENCLAVE_INGRESS
    ENCLAVE_INGRESS -->|"TCP"| APP
```

### Egress Traffic Flow

```mermaid
graph LR
    subgraph "Enclave"
        APP["User Application"]
        ENCLAVE_EGRESS["EnclaveHttpProxy<br/>(HTTP Proxy)"]
    end
    
    subgraph "Docker Container (Host)"
        HOST_EGRESS["HostHttpProxy<br/>(vsock → network)"]
    end
    
    subgraph "External"
        EXTERNAL["External Services<br/>(APIs, KMS, etc.)"]
    end
    
    APP -->|"HTTP/HTTPS<br/>(via http_proxy)"| ENCLAVE_EGRESS
    ENCLAVE_EGRESS -->|"vsock"| HOST_EGRESS
    HOST_EGRESS -->|"TCP"| EXTERNAL
```

### KMS Attestation Flow

```mermaid
graph LR
    subgraph "Enclave"
        APP["User Application"]
        KMS_PROXY["KMS Proxy<br/>(adds attestation)"]
        NSM["NSM Driver<br/>(attestation)"]
    end
    
    subgraph "Egress Path"
        EGRESS["Egress Proxies"]
    end
    
    subgraph "AWS"
        KMS["AWS KMS"]
    end
    
    APP -->|"KMS Request"| KMS_PROXY
    KMS_PROXY -->|"Get attestation"| NSM
    NSM -->|"Attestation doc"| KMS_PROXY
    KMS_PROXY -->|"Request + Recipient"| EGRESS
    EGRESS -->|"HTTPS"| KMS
    KMS -->|"Response"| EGRESS
    EGRESS -->|"Encrypted response"| KMS_PROXY
    KMS_PROXY -->|"Decrypted data"| APP
```

---

## Data Flow Diagrams

### Complete Runtime Architecture

```mermaid
graph TB
    subgraph "Host Machine"
        subgraph "Docker Container"
            SLEEVE["Sleeve<br/>(enclaver-run)"]
            NITRO_CLI["nitro-cli"]
            
            subgraph "Host-Side Proxies"
                HOST_INGRESS["HostProxy<br/>(Ingress)"]
                HOST_EGRESS["HostHttpProxy<br/>(Egress)"]
            end
        end
        
        DEV["(/dev/nitro_enclaves)"]
    end
    
    subgraph "Enclave VM"
        ODYN["Odyn Supervisor"]
        
        subgraph "Odyn Services"
            ENCLAVE_INGRESS["Ingress Proxy"]
            ENCLAVE_EGRESS["Egress Proxy"]
            KMS_PROXY["KMS Proxy"]
            API["API Server"]
            HELIOS["Helios RPC"]
            CONSOLE["Console<br/>(Log Capture)"]
            LAUNCHER["Launcher"]
        end
        
        APP["User Application"]
    end
    
    EXTERNAL_CLIENT["External Clients"]
    EXTERNAL_SERVICES["External Services"]
    
    %% Connections
    DEV -.-> NITRO_CLI
    SLEEVE --> NITRO_CLI
    NITRO_CLI --> ODYN
    
    ODYN --> ENCLAVE_INGRESS
    ODYN --> ENCLAVE_EGRESS
    ODYN --> KMS_PROXY
    ODYN --> API
    ODYN --> HELIOS
    ODYN --> CONSOLE
    ODYN --> LAUNCHER
    
    LAUNCHER --> APP
    
    EXTERNAL_CLIENT --> HOST_INGRESS
    HOST_INGRESS -->|"vsock"| ENCLAVE_INGRESS
    ENCLAVE_INGRESS --> APP
    
    APP --> ENCLAVE_EGRESS
    ENCLAVE_EGRESS -->|"vsock"| HOST_EGRESS
    HOST_EGRESS --> EXTERNAL_SERVICES
    
    APP --> CONSOLE
    CONSOLE -->|"vsock<br/>port 17001"| SLEEVE
    ODYN -->|"vsock<br/>port 17000"| SLEEVE
```

### VSOCK Communication Ports

| Port | Direction | Purpose |
|------|-----------|---------|
| 17000 | Enclave → Host | Status updates (JSON stream) |
| 17001 | Enclave → Host | Application logs (stdout/stderr) |
| 17002 | Enclave → Host | HTTP egress proxy traffic |
| Dynamic | Host → Enclave | Ingress connections (per listener) |

---

## Summary

The Enclaver architecture provides a complete isolation solution:

1. **User Application**: Your backend service that needs to run in a trusted execution environment

2. **Odyn Supervisor**: The enclave-side component that:
   - Bootstraps the enclave environment
   - Provides networking proxies (ingress/egress)
   - Manages KMS attestation
   - Supervises the application lifecycle

3. **EIF File**: The encrypted enclave image containing:
   - Odyn supervisor
   - User application
   - Configuration

4. **Sleeve Program**: The host-side orchestrator that:
   - Launches the enclave via nitro-cli
   - Provides host-side proxies
   - Streams logs and status

5. **nitro-cli**: AWS tool for enclave lifecycle management

6. **Docker Image**: The complete package containing:
   - Sleeve program
   - nitro-cli
   - EIF file
   - Configuration

This architecture ensures that sensitive workloads run in an isolated, attested environment while maintaining connectivity with external services through carefully controlled proxy channels.

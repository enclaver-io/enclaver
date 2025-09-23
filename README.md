<img src="docs/img/enclaver-logo-color.png" width="350" />

Enclaver is an open source toolkit created to enable easy adoption of software enclaves, for new and existing backend software.

<a href="https://discord.gg/a5CvXkNWYF"><img src="docs/img/enclaver-discord.svg" height="30" /></a>

Enclaves provide several critical features for operating software which processes sensitive data, including:

 - **Isolation:** Enclaves enable a deny-by-default approach to accessing process memory. Software running in an enclave can expose interfaces for accessing specific data, while disallowing humans or other software on the same computer from reading arbitrary data from memory.
 - **Attestation:** Enclaves make it possible to determine the exact identity and configuration of software running in an enclave.
 - **Network Restrictions:** External communication is limited and controlled. The network policy is built into the image and therefore the software attestation.

These demos show off how your apps can use these unique features to improve privacy and security:

 - [Run a simple Python app](https://enclaver.io/docs/0.x/guide-app/) that represents a microservice or security-centric function
 - [Run Hashicorp Vault](https://enclaver.io/docs/0.x/guide-vault/) to fully isolate it after it's unsealed

<a href="https://www.youtube.com/watch?v=nxSgRYten1o"><img src="docs/img/thumb-run.png" width="400" /></a>

## Project State

Enclaver is currently in beta and should be used cautiously in production. Enclaver currently only supports [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/); support for Azure Confidential VMs, GCP Confidential VMs, and arbitrary SGX and OP-TEE enclaves is on the roadmap.

 - [Getting started guide](https://enclaver.io/docs/0.x/getting-started/)
 - [Deploy an enclave on AWS](https://enclaver.io/docs/0.x/deploy-aws/)
 - [Deploy an enclave on Kubernetes](https://enclaver.io/docs/0.x/deploy-kubernetes/)

## Architecture

Read the [architecture doc](https://enclaver.io/docs/0.x/architecture/) for the full details. Enclaver consists of 3 interrelated pieces of software: 

 - `enclaver` CLI for build and run
 - “Outer Proxy” + Enclave Supervisor
 - “Inner Proxy” + Process Supervisor

<img src="docs/img/diagram-enclaver-components.svg" width="800" />

## FAQ

See [the FAQ](https://enclaver.io/docs/0.x/faq/) for common questions and a comparison of Enclaver to similar technologies.


## Reporting Security Bugs

Report security bugs confidentially at security@enclaver.io

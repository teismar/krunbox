# Security Policy

## Security Model Overview

**krunbox** is designed to isolate autonomous AI coding agents and untrusted development workloads. The isolation model enforces the following boundaries:

1. **Hardware Virtualization Boundary**:
   MicroVMs run on `crun-krun` with isolated Linux guest kernels via `/dev/kvm`. Compromising guest processes cannot directly compromise the host kernel.
2. **Egress Firewall Enforcement**:
   Network policies (`ai-only`, `dev-common`, `offline`, `custom`) are enforced at the host network namespace boundary via netns filtering and `pasta --no-map-gw`. Guest processes cannot bypass egress restrictions even with in-guest root privileges.
3. **Workspace Integrity**:
   `.git/hooks` is mounted read-only by default (`protect_git_hooks=True`) to prevent malicious autonomous workflows from planting hooks that run on the host outside the VM.
4. **Scoped Secrets Management**:
   Host secrets are staged into microVM memory through temporary, zero-wiped `--env-file` mounts rather than persistent disk storage.

## Reporting a Security Vulnerability

If you discover a security vulnerability or sandbox escape in krunbox, please do not disclose it publicly in issues or pull requests.

Instead, please report it via private disclosure:
- Email: **eismartim@gmail.com**
- Subject: `[Security] Vulnerability Report: <Brief Description>`

Please include:
- A description of the vulnerability and attack vector.
- Steps to reproduce or proof-of-concept script.
- Potential impact on the host system or network boundary.

We will acknowledge receipt within 48 hours and work with you on a resolution prior to public release.

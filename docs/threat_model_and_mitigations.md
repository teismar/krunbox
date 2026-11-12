# Security & Threat Model: What krunbox Protects (and What It Doesn't)

When you run autonomous AI coding agents (Claude Code, OpenDevin, Aider, custom scripts), you are handing an automated tool a shell with the ability to execute arbitrary commands.

Autonomous tools can suffer from hallucinations, buggy third-party packages, or **indirect prompt injection** (where an agent reads an untrusted README, code comment, or issue containing hidden instructions).

This document explains what krunbox protects you from, how the security boundaries work, and what risks remain so you can use it safely.

---

## What krunbox Protects Against

### 1. Host Kernel Compromise (KVM MicroVM vs. Docker)
- **The Risk**: Standard Docker/Podman containers share your host Linux kernel. If an agent runs with elevated permissions or triggers a kernel vulnerability, it can escape the container and compromise your entire machine.
- **The Defense**: `krunbox` runs every sandbox inside an actual lightweight Linux microVM powered by `crun-krun`, `libkrun`, and KVM (`/dev/kvm`). The guest kernel is completely separate from your host kernel. If the guest kernel panics or is exploited, your host remains unaffected.

### 2. Network Secret Exfiltration & LAN Probing
- **The Risk**: An agent could be tricked into reading credentials and sending them to an external server, or scanning your local Wi-Fi and NAS devices.
- **The Defense**:
  - Outbound egress profiles (`offline`, `ai-only`, `dev-common`, `custom`) restrict where the agent can connect.
  - With `ai-only`, the sandbox can only communicate with approved AI API providers (Anthropic, OpenAI, Gemini, etc.). It cannot ping arbitrary IP addresses or scan your local network.
  - With `offline`, all network interfaces except loopback are shut down.

### 3. In-Guest Firewall Tampering (`sudo nft flush`)
- **The Risk**: Many developer workflows need `sudo` inside the sandbox (e.g. to install packages via `apt` or run an inner Docker daemon). If an untrusted process has `sudo`, it could run `sudo nft flush` and disable the firewall.
- **The Defense**:
  - `krunbox` drops `CAP_NET_ADMIN` inside the guest microVM (`setpriv --bounding-set=-net_admin`).
  - Network firewall filtering is applied on the **host network namespace** outside the guest microVM boundary (`pasta --no-map-gw`).
  - Even with `root` privileges inside the microVM, the guest cannot modify the network filters enforced on the outside.

### 4. Git Hook Poisoning (`.git/hooks/pre-commit`)
- **The Risk**: An agent modifying your project workspace could write a malicious bash script into `.git/hooks/pre-commit` or `.git/hooks/post-checkout`. When you later run `git commit` or `git checkout` on your host machine, that script executes with your host user privileges.
- **The Defense**: `krunbox` automatically bind-mounts `/workspace/.git/hooks` **read-only** (`:ro`) by default. Any attempt by guest processes to modify git hooks immediately fails.

### 5. Accidental Host Filesystem Wipes
- **The Risk**: A hallucinated `rm -rf /` or bad script wipes host files.
- **The Defense**: Only the explicit workspace directory you chose (`-w /path/to/project`) is mounted into the guest. The rest of your host filesystem (`/home`, `/etc`, `/var`, `/root`) is completely invisible and unreachable from inside the microVM.

### 6. Malicious SSH Directive Injection
- **The Risk**: An untrusted directory or sandbox name could contain OpenSSH directives (e.g. `ProxyCommand`, `LocalCommand`) intended to trigger arbitrary code execution on your host when running `ssh`.
- **The Defense**: Sandbox names and aliases are strictly validated against `^[a-zA-Z0-9_-]+$`. SSH config files are strictly isolated in `~/.ssh/config.d/` with path traversal protections.

---

## What krunbox Does NOT Protect Against (Current Boundaries)

Honesty about security boundaries is essential. Here are the things you should keep in mind:

### 1. Workspace Contents Can Be Modified
The sandbox is designed so the agent can write code in your project directory (`/workspace`). If an agent deletes a file or writes buggy code inside `/workspace`, that change happens on your disk.
- **Mitigation**: krunbox takes an automatic pre-run snapshot before the sandbox starts. Use `krunbox diff <name>` to review changes, and `krunbox rollback <name>` to restore your files if things went wrong.

### 2. In-Guest Environment Secrets
If you pass an API key directly into the container via `-e ANTHROPIC_API_KEY=...` or an env file, any process running inside that sandbox can read it. If an agent is tricked into echoing its environment, the key could be leaked in a commit or outbound request.
- **Mitigation**: Use restricted egress (`ai-only`) so requests can only go to official AI endpoints, and check our [Future Ideas Roadmap](future_ideas.md) for the upcoming Zero-Secret Host API Proxy.

### 3. Dynamic CDN IP Addresses
Frontier model endpoints (like OpenAI or Anthropic) sit behind CDNs (Cloudflare, CloudFront) whose IP addresses can shift over time. krunbox resolves domain IPs when generating the firewall rules. If a CDN shifts to an unlisted IP, you may need to reload the network policy (`krunbox edit <name>`).

### 4. Fallback Without Hardware KVM
If you run krunbox on a machine where `/dev/kvm` is missing (such as an un-nested cloud VM), krunbox falls back to rootless Podman containers. While rootless Podman isolates host user IDs, it shares the host kernel. Run `krunbox doctor` to ensure KVM hardware acceleration is active.

---

## Best Practices for Safe Sandboxing

1. **Keep Egress Locked Down**: Use `--network ai-only` for AI coding agents that don't need general internet browsing.
2. **Leave Git Hooks Protected**: Keep `--protect-git-hooks` enabled (it is on by default).
3. **Inspect the Diff Before Host Commits**: Run `krunbox diff <name>` or open the Workspace Changes dialog in the GUI before committing code on your host.
4. **Use Ephemeral Sandboxes for Scratch Work**: Ephemeral mode discards all container state upon exit, preventing cruft accumulation.
5. **Run Diagnostics**: If something feels off, run `krunbox doctor` to verify system permissions and runtime health.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-11-12

### Added
- **Native Libadwaita & GTK4 Desktop Console**: Modern GNOME desktop interface (`io.krunbox.Krunbox`) featuring interactive sandbox management, live status badges, and dark/light system styling.
- **Dual Resource Meters**: Real-time CPU utilization (normalized percentage) and RAM memory meters (`Gtk.LevelBar`) with VmRSS microVM tracking.
- **1-Click IDE Launchers**: Split button launcher with direct shortcuts for VS Code, Cursor, Zed, JetBrains Gateway, and SFTP file management.
- **MicroVM Engine & Fallback Architecture**: Hardware-isolated microVM virtualization powered by `crun-krun` and `libkrun` using Linux KVM (`/dev/kvm`), with seamless fallback to rootless Podman containers.
- **Outbound Egress Firewall**: Strict policy-based network egress control (`offline`, `ai-only`, `dev-common`, `full`, `custom`) using nftables and local dnsmasq resolution.
- **Blacklist Priority Filtering**: Denied domains and IP ranges are evaluated and dropped first before any allow rules across all profiles.
- **Workspace Git Guardrails**: Automatic read-only mounting of `/workspace/.git/hooks` (`protect_git_hooks=True`) to prevent malicious prompt-injection hooks.
- **Workspace Snapshots & Diff Inspection**: Automated baseline snapshots with interactive modal visual diff viewer (`WorkspaceChangesDialog`) to review file modifications.
- **Scoped Secrets Vault**: Zero-plaintext secret injection into microVM memory via ephemeral env files without persisting sensitive tokens to disk.
- **OpenSSH Configuration Integration**: Automatic generation of isolated SSH client configurations in `~/.ssh/config.d/` with alphanumeric name validation and path traversal defenses.
- **Comprehensive Command-Line Interface**: `krunbox` CLI tool with full support for `run`, `create`, `start`, `stop`, `delete`, `list`, `ssh`, `connect`, `network`, `doctor`, `ports`, `secrets`, `snapshot`, `install-desktop`, and `ui`.
- **System Diagnostics**: Built-in `krunbox doctor` command and GUI dialog verifying KVM, crun-krun, libkrun, passt/pasta, rootless subuids, and desktop dependencies.
- **Native OS Packaging**: Automated packaging for Debian/Ubuntu (`.deb`), Fedora 45 / RHEL (`.rpm`), and Python wheels/sdist.

### Changed
- Complete architectural redesign from single shell script prototype to production-grade Python package and GTK4 / Libadwaita desktop application.
- Upgraded target platform support to modern Linux distributions including Fedora 45 and Ubuntu 24.04+.

### Removed
- Deprecated legacy monolithic runner script in favor of modular `krunbox.core`, `krunbox.cli`, and `krunbox.ui` architecture.

## [1.0.0] - 2026-10-31

### Added
- Initial proof-of-concept release.
- Standalone shell script (`run.sh`) to launch an AI agent environment inside a basic libkrun microVM.
- Direct KVM hardware acceleration support via `/dev/kvm`.
- Interactive pseudo-terminal entrypoint for development tasks.

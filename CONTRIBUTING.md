# Contributing to krunbox

Thank you for your interest in contributing to **krunbox**!

## Development Environment Setup

krunbox runs microVMs via `crun-krun`, Linux KVM, and rootless Podman with a native GTK4 / Libadwaita user interface.

### Prerequisites

- **Linux Kernel**: With `/dev/kvm` hardware virtualization support.
- **Runtimes**: Podman (>= 4.9), `crun-krun`, `passt`/`pasta`.
- **System Libraries**: GTK4 (>= 4.10), Libadwaita (>= 1.5), `python3-gobject`, `desktop-file-utils`, `appstream`.
- **Python**: 3.10+ with `rich`.

### Local Installation

Clone the repository and install development dependencies via `make`:

```bash
git clone https://github.com/teismar/krunbox.git
cd krunbox
make install
```

## Running Tests and Validation

A unified `Makefile` is provided so local development and GitHub Actions CI run identical checks:

```bash
# Show all available development targets
make help

# Run validation and full test suite (same as CI)
make check

# Run individual checks
make validate    # Validate desktop file, AppStream XML, and icon cache
make test        # Run the full pytest suite under Xvfb
make test-fast   # Quick test run in quiet mode
make doctor      # Run virtualization and system diagnostics
make ui          # Launch the GTK4 desktop GUI locally
```

## Design Principles & Coding Standards

1. **Native Libadwaita First**:
   - Use stock GTK4 and Libadwaita widgets (`Adw.ApplicationWindow`, `Adw.PreferencesDialog`, `Adw.AlertDialog`, `Adw.ActionRow`, `Gtk.LevelBar`, `Gtk.FileDialog`).
   - Do not inject hardcoded custom CSS or override `.card` / `.pill` styles with hardcoded dark-mode hex values.
   - Rely on semantic color classes (`.success`, `.warning`, `.error`, `.accent`, `.dim-label`).

2. **Security & Sandboxing Invariants**:
   - Never expose raw host secrets inside guest microVM disks or persistent volumes.
   - Mask `.git/hooks` read-only by default to prevent untrusted agents from dropping host hooks.
   - Enforce network egress policies outside the guest microVM boundary via netns filtering and `pasta --no-map-gw`.

3. **Pull Request Workflow**:
   - Keep commits focused and well-scoped using conventional commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
   - Ensure the full test suite passes locally before submitting.

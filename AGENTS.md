# AGENTS.md - Krunbox Engineering & Design Principles

This document serves as the single source of truth for engineering agents and human developers maintaining **krunbox**. It captures critical design principles, architectural decisions, and visual identity invariants. For full specifications, refer to the linked reference documents.

---

## 1. Core Visual Principles & Design Philosophy

- **Native Libadwaita & GTK4 First (Zero Custom-CSS Hijacking, Zero "AI Slob")**:
  - Prefer stock Libadwaita and GTK4 widgets (`Adw.ApplicationWindow`, `Adw.ToolbarView`, `Adw.HeaderBar`, `Adw.PreferencesPage`, `Adw.PreferencesGroup`, `Adw.ActionRow`, `Adw.EntryRow`, `Adw.SpinRow`, `Adw.ComboRow`, `Adw.SwitchRow`, `Adw.ExpanderRow`, `Adw.ViewStack`, `Adw.ViewSwitcher`, `Adw.StatusPage`, `Adw.Banner`, `Adw.Clamp`, `Gtk.LevelBar`) with minimal custom CSS.
  - Never override built-in Libadwaita classes like `.pill` or `.card` with hardcoded dark-theme hex colors, and never construct artificial web-like badges with oversized monospace text or neon borders (`[PASS]`, `[WARN]`, `[FAIL]`).
  - Rely exclusively on native Libadwaita semantic colors (`.success`, `.warning`, `.error`, `.accent`, `.dim-label`) and standard Adwaita symbolic icons (`emblem-ok-symbolic`, `dialog-warning-symbolic`, `dialog-error-symbolic`).
- **Detailed Reference**: See [**docs/design_system.md**](file:///workspace/docs/design_system.md).

---

## 2. Logo & Branding Invariants

- **Master Logo**: Simple, unicolor vector glyph rendered in GNOME Accent Cobalt (`#3584e4`).
  - **Outer Chassis**: Symmetrical 128×128 rounded container with 18px radius and 9px stroke, representing microVM hardware isolation.
  - **Top Notch**: Recessed horizontal hardware management slot (`width: 68px`, `height: 7px`).
  - **Whitespace Rule 1 (Stem to Chevron)**: An intentional, balanced whitespace gap (5px) separates the vertical pillar `|` and the diagonal chevron `>`.
  - **Whitespace Rule 2 (Diagonal Junction)**: The two diagonal arms meet solidly and seamlessly at the vertex. There is **zero gap, zero notch, and zero whitespace** where the upper and lower diagonal lines meet.
- **Symbolic Icon**: Monochrome 16×16 vector (`io.krunbox.Krunbox-symbolic.svg`) with pixel-aligned paths using `#2e3436` / `currentColor` for GNOME Shell top bar and search integration.
- **Detailed Reference**: See [**docs/design_system.md § 2**](file:///workspace/docs/design_system.md#2-logo--emblem-specification).

---

## 3. GNOME App Manager & Desktop Integration

- **Application ID**: `io.krunbox.Krunbox` (matches GTK `application_id` and `StartupWMClass`).
- **Desktop Entry**: [`krunbox/data/io.krunbox.Krunbox.desktop`](file:///workspace/krunbox/data/io.krunbox.Krunbox.desktop), validated via `desktop-file-validate`.
- **AppStream MetaInfo**: [`krunbox/data/io.krunbox.Krunbox.metainfo.xml`](file:///workspace/krunbox/data/io.krunbox.Krunbox.metainfo.xml), validated via `appstreamcli validate --no-net`. Required for GNOME App Manager & Software catalog indexing.
- **Hicolor Hierarchy**: Vector SVGs in `scalable/apps` and `symbolic/apps`, plus pre-rasterized PNGs across 8 standard resolutions (16×16 to 512×512).
- **Auto-Installation**: `krunbox ui` checks `~/.local/share/applications` on launch and self-installs if missing. Users can also run `krunbox install-desktop`.

---

## 4. Architecture & Security Invariants

- **MicroVM Engine**: Hardware virtualization backed by `crun-krun` and `libkrun` using Linux KVM (`/dev/kvm`), with Podman rootless fallback.
- **Zero Mentions of SBX**: No file, folder, variable, or CLI command may use `sbx`.
- **Egress Firewall (Dual Whitelist & Blacklist Filtering)**:
  - Strict policy-based network egress (`offline`, `ai-only`, `dev-common`, `full`, `custom`).
  - **Blacklist Precedence**: Blacklisted / denied domains are evaluated and dropped **first** before any allow rules. Blacklisting functions across all profiles, including `full`.
  - **Custom Whitelist Augmentation**: Whitelisted domains extend profile defaults or define standalone custom allowances.
  - **Subcommand & Flags**: Available via `--allow` / `--whitelist` and `--deny` / `--blacklist` on `run`/`create`, and dynamically inspectable via `krunbox network <name>`.
- **OpenSSH Configuration Security**:
  - `write_sandbox_ssh_config` validates sandbox names and aliases against strict alphanumeric patterns (`^[a-zA-Z0-9_-]+$`) to prevent OpenSSH directive injection (e.g. `ProxyCommand`, `LocalCommand`).
  - Path traversal protection guarantees config files strictly reside within `~/.ssh/config.d/`.
- **Egress Script Isolation & Safe Generation**:
  - Egress scripts are generated in private user storage (`~/.local/share/krunbox/egress`, mode `0700`) rather than public `/tmp` to prevent symlink race and overwrite attacks.
  - Profile names are strictly restricted to allowlisted profiles (`full`, `ai-only`, `dev-common`, `offline`, `custom`).
  - All IP elements in nftables sets are strictly validated IPv4 addresses.
- **Port Security & Process Isolation**:
  - All port specifications enforce TCP boundaries (`1 <= port <= 65535`).
  - Dynamic SSH port tunnels scope `pgrep` and `pkill` to the current user ID (`-u <uid>`) to prevent cross-user process interference.
  - SSH tunnel connections enforce `--` option separation.
- **Detailed Reference**: See [**docs/architecture.md**](file:///workspace/docs/architecture.md) and [**docs/threat_model_and_mitigations.md**](file:///workspace/docs/threat_model_and_mitigations.md).

---

## 5. Testing & Verification Requirements

- **Suite Execution**: Always run test suites under virtual display:
  ```bash
  xvfb-run -a pytest -v /workspace/tests
  ```
- **Validation Tools**:
  - `desktop-file-validate <desktop_file>` must pass with 0 errors.
  - `appstreamcli validate --no-net <metainfo_file>` must pass with 0 warnings.
  - `gtk4-update-icon-cache -f -t <icon_dir>` must succeed.

---

## 6. Rootless Host & Storage Environment Invariants

- **Rootless Podman Storage Subsystem**: On filesystems lacking native subuid shifting (e.g. `virtiofs`), rootless Podman requires a tmpfs mount for storage (`/home/vscode/.local/share/containers/storage`) configured with `driver = "overlay"` and `mount_program = "/usr/bin/fuse-overlayfs"`.
- **Rootless Kernel Permissions**: `/dev/net/tun` (for passt/pasta user networking) and `/dev/fuse` (for fuse-overlayfs) must have 0666 permissions (`chmod 666 /dev/net/tun /dev/fuse`).
- **Buildah Temporary Storage**: Image build contexts require `TMPDIR` pointing to a subuid-capable filesystem (`/home/vscode/.local/share/containers/storage/tmp`).
- **Background Detached Sandboxes**: Detached daemon sandboxes (`-d`) must allocate a pseudo-TTY (`-t`) to ensure interactive entrypoint shells (such as `/bin/bash`) remain resident and do not terminate on stdin EOF.
- **Diagnostics**: `krunbox doctor` actively verifies KVM, microVM runtimes, passt, podman subuids, `/dev/net/tun`, `/dev/fuse`, GTK4/Libadwaita, and OpenSSH.

---

## 7. Quick Connect & Terminal Integration Invariants

- **Terminal Emulator Discovery**: `launch_ssh_terminal` tests prioritized candidates: `ptyxis` (Fedora 41+ default), `gnome-terminal`, `kgx`, `xdg-terminal-exec`, `x-terminal-emulator`, `alacritty`, `kitty`, `wezterm`, `foot`, `ghostty`, `konsole`, `xfce4-terminal`, `terminator`, `tilix`, and `xterm`.
- **Interactive Auto-Resume**: Triggering Quick Connect (via UI card button, double-click gesture, or CLI `krunbox connect / ssh`) on a stopped microVM automatically resumes the instance before opening the SSH connection.
- **Clipboard Fallback**: In environments without a graphical terminal emulator, `krunbox` writes `ssh <target>` to the system clipboard and displays a native toast notification.
- **CLI Invariant**: Supported via `krunbox ssh [target] [-t/--terminal]` and alias `krunbox connect [target] [-t/--terminal]`.

---

## 8. Workspace Directory Picker & Validation Invariants

- **Folder Chooser Integration**:
  - `CreateSandboxDialog` includes a flat action suffix button on `Workspace Directory` with icon `folder-open-symbolic`.
  - Uses `Gtk.FileDialog` with initial folder pre-selection and fallback to `Gtk.FileChooserDialog` across container/portal environments.
- **Non-Existent Directory Real-Time Warning**:
  - Live inspection on every entry text change (`_on_dir_changed` -> `_check_dir_exists`).
  - Displays inline warning suffix `dialog-warning-symbolic` (`.warning`) and reveals top `Adw.Banner` informing the user that the folder does not exist on disk.
- **In-Place Directory Creation**:
  - Banner includes "Create Folder" button to immediately create missing directory hierarchy (`mkdir(parents=True)`), clear warnings, and dismiss the banner.
  - Launch button triggers `Adw.MessageDialog` ("Create Workspace Directory?") if invoked with a non-existent path, offering "Create & Launch" (`SUGGESTED`) to avoid dead-ends.
- **Detailed Reference**: See [**docs/design_system.md § 4**](file:///workspace/docs/design_system.md#4-dialogs-banners--form-validation-patterns).

---

## 9. Dual CPU & RAM Utilization Meters & 1-Click IDE Launchers

- **Functioning Resource LevelBars**:
  - `SandboxCard` maintains distinct `Gtk.LevelBar` instances for CPU (`cpu_bar`) and RAM (`ram_bar`).
  - CPU percentage is normalized against 100% (or clamped 0.0 to 1.0).
  - RAM percentage is computed against the sandbox's actual allocated `ram_mib` (with fallback to `/proc/<pid>/status` `VmRSS` for crun-krun microVMs).
- **1-Click IDE Split Button**:
  - `connect_btn` is implemented as an `Adw.SplitButton` with `utilities-terminal-symbolic` main action and dropdown actions for VS Code, Cursor, Zed, JetBrains Gateway, and SFTP File Manager. The dropdown button portion explicitly configures a standard downward arrow symbolic icon (`go-down-symbolic` / `pan-down-symbolic`) to ensure high-contrast visibility across Fedora and non-standard GTK/icon desktop themes.
  - Leak prevention invariant: `SandboxCard.cleanup()` must call `self.connect_btn.set_menu_model(None)` before card disposal.

---

## 10. Workspace Git Guardrails, Snapshots & Host-Boundary Egress Lockdown

- **Git Hook Masking**: Always mount `/workspace/.git/hooks` read-only (`:ro`) by default (`protect_git_hooks=True`).
- **Pre-Run Snapshots & Rollback**: Automatic pre-run baseline capture via `WorkspaceSnapshotManager`. Interactive inspection via `WorkspaceChangesDialog`.
- **Host-Boundary Egress Lockdown**: Enforced outside the guest microVM boundary via rootless netns filtering and `pasta --no-map-gw`. Sudoers restriction and capability bounding set drop `CAP_NET_ADMIN` inside the guest.
- **Scoped Secrets Vault**: Pass secrets into microVM memory via zero-wiped `--env-file` without writing plaintext `.env` files onto host workspace disk.



# Design Principles & Visual Identity

**krunbox** is built for developers who care about clean, fast software on Linux.

When designing the graphical desktop app (`krunbox ui`), we had one overriding goal: **build a first-class Linux citizen using native GTK4 and Libadwaita, not another bloated Electron web wrapper.**

---

## 1. Why Libadwaita?

1. **Lightweight & Fast**:
   - `krunbox ui` starts instantly and uses ~30 MB of resident memory.
   - Contrast this with Electron-based tools that often swallow 300–500 MB of RAM just to render a couple of cards and buttons. On a developer machine where RAM is better spent on compilers, Docker, and LLM inference, every megabyte counts.
2. **Native GNOME Integration**:
   - Automatically respects your system-wide dark/light theme preferences and GNOME accent color.
   - Uses standard GNOME keyboard shortcuts (`Ctrl+N` for new sandbox, `Ctrl+,` for preferences, `Ctrl+Q` to quit).
   - Crisp rendering on HiDPI and fractional scaling displays under Wayland.
3. **Consistency & Accessibility**:
   - Adheres to GNOME Human Interface Guidelines (HIG).
   - Uses stock Libadwaita widgets (`Adw.ApplicationWindow`, `Adw.ToolbarView`, `Adw.PreferencesPage`, `Adw.ActionRow`, `Adw.SplitButton`, `Adw.Banner`, `Gtk.LevelBar`) so the application looks and feels completely natural on modern Linux distributions.

---

## 2. The "No AI Slob" Principle

Many modern tools suffer from over-styled, web-like UI clutter. In krunbox, we strictly avoid:
- Hardcoded hex colors that break light mode or high-contrast themes.
- Artificial web-style status pills with neon borders or loud monospace tags (`[PASS]`, `[WARN]`, `[FAIL]`).
- Custom CSS hacks that fight against the system stylesheet.

Instead, we rely exclusively on:
- **Libadwaita Semantic Classes**: `.success` (green), `.warning` (amber), `.error` (red), `.accent` (blue), and `.dim-label` (subtle secondary text).
- **Standard Symbolic Icons**: `emblem-ok-symbolic`, `dialog-warning-symbolic`, `dialog-error-symbolic`, `utilities-terminal-symbolic`.
- **Native LevelBars**: Stock `Gtk.LevelBar` widgets for normalized CPU and RAM meters.

---

## 3. Key UI Components

| Component | Libadwaita Widget | Purpose |
|---|---|---|
| **Sandbox Card** | `Gtk.ListBoxRow` + `.card` | Shows sandbox name, status badge, CPU/RAM LevelBars, and quick actions |
| **1-Click IDE Button** | `Adw.SplitButton` | Primary action opens a terminal; dropdown connects via VS Code, Cursor, Zed, or JetBrains |
| **Resource Meters** | `Gtk.LevelBar` | Visual real-time CPU (0–100%) and RAM usage against allocated limits |
| **New Sandbox Dialog** | `Adw.PreferencesDialog` | Clean form with directory picker, image selector, resource sliders, and network profile |
| **Egress Traffic Dialog** | `Adw.PreferencesDialog` | Live table of outbound domain requests with 1-click allow/block buttons |
| **Diff & Rollback Viewer** | `Adw.PreferencesDialog` | Colorized unified diff viewer showing modified files before you accept agent changes |

#!/usr/bin/env bash
set -euo pipefail

# Determine repository root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_DIR}"

VERSION=$(grep -m1 '^version = ' pyproject.toml | cut -d'"' -f2)
ARCH="all"
PKG_NAME="krunbox"
DEB_NAME="${PKG_NAME}_${VERSION}_${ARCH}.deb"
DIST_DIR="${REPO_DIR}/dist"
STAGING_DIR="${REPO_DIR}/build/deb-staging"

echo "==> Building Debian package for ${PKG_NAME} v${VERSION} (${ARCH})..."

# Clean build staging
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}"
mkdir -p "${DIST_DIR}"

# 1. Python package installation
PYTHON_TARGET="${STAGING_DIR}/usr/lib/python3/dist-packages"
mkdir -p "${PYTHON_TARGET}"
cp -a krunbox "${PYTHON_TARGET}/"
find "${PYTHON_TARGET}" -type d -name "__pycache__" -exec rm -rf {} +
find "${PYTHON_TARGET}" -type f -name "*.pyc" -delete

# 2. CLI Executable wrappers
BIN_DIR="${STAGING_DIR}/usr/bin"
mkdir -p "${BIN_DIR}"

cat <<'EOF' > "${BIN_DIR}/krunbox"
#!/bin/sh
exec /usr/bin/python3 -m krunbox.cli.main "$@"
EOF
chmod 0755 "${BIN_DIR}/krunbox"

cat <<'EOF' > "${BIN_DIR}/krunbox-ui"
#!/bin/sh
exec /usr/bin/python3 -m krunbox.ui.app "$@"
EOF
chmod 0755 "${BIN_DIR}/krunbox-ui"

# 3. Desktop Entry and AppStream Metainfo
APP_DIR="${STAGING_DIR}/usr/share/applications"
META_DIR="${STAGING_DIR}/usr/share/metainfo"
mkdir -p "${APP_DIR}" "${META_DIR}"

cp "${REPO_DIR}/krunbox/data/io.krunbox.Krunbox.desktop" "${APP_DIR}/"
cp "${REPO_DIR}/krunbox/data/io.krunbox.Krunbox.metainfo.xml" "${META_DIR}/"
chmod 0644 "${APP_DIR}/io.krunbox.Krunbox.desktop"
chmod 0644 "${META_DIR}/io.krunbox.Krunbox.metainfo.xml"

# 4. Bash Completion
COMP_DIR="${STAGING_DIR}/usr/share/bash-completion/completions"
mkdir -p "${COMP_DIR}"
cp "${REPO_DIR}/krunbox/data/krunbox.bash-completion" "${COMP_DIR}/krunbox"
chmod 0644 "${COMP_DIR}/krunbox"

# 5. Icons
ICON_BASE="${STAGING_DIR}/usr/share/icons/hicolor"
for size in 16 24 32 48 64 128 256 512; do
    TARGET_ICON_DIR="${ICON_BASE}/${size}x${size}/apps"
    mkdir -p "${TARGET_ICON_DIR}"
    cp "${REPO_DIR}/krunbox/data/icons/${size}x${size}/io.krunbox.Krunbox.png" "${TARGET_ICON_DIR}/"
    chmod 0644 "${TARGET_ICON_DIR}/io.krunbox.Krunbox.png"
done

mkdir -p "${ICON_BASE}/scalable/apps"
cp "${REPO_DIR}/krunbox/data/icons/io.krunbox.Krunbox.svg" "${ICON_BASE}/scalable/apps/"
chmod 0644 "${ICON_BASE}/scalable/apps/io.krunbox.Krunbox.svg"

mkdir -p "${ICON_BASE}/symbolic/apps"
cp "${REPO_DIR}/krunbox/data/icons/io.krunbox.Krunbox-symbolic.svg" "${ICON_BASE}/symbolic/apps/"
chmod 0644 "${ICON_BASE}/symbolic/apps/io.krunbox.Krunbox-symbolic.svg"

# 6. Documentation and License
DOC_DIR="${STAGING_DIR}/usr/share/doc/${PKG_NAME}"
mkdir -p "${DOC_DIR}"
cp "${REPO_DIR}/LICENSE" "${DOC_DIR}/copyright"
cp "${REPO_DIR}/README.md" "${DOC_DIR}/"
chmod 0644 "${DOC_DIR}/copyright" "${DOC_DIR}/README.md"

# 7. Package Control and Maintainer Scripts
DEBIAN_DIR="${STAGING_DIR}/DEBIAN"
mkdir -p "${DEBIAN_DIR}"

INSTALLED_SIZE=$(du -sk "${STAGING_DIR}" | cut -f1)

cat <<EOF > "${DEBIAN_DIR}/control"
Package: ${PKG_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_SIZE}
Maintainer: teismar <eismartim@gmail.com>
Depends: python3 (>= 3.10), python3-rich (>= 13.0.0), python3-gi, gir1.2-gtk-4.0, gir1.2-adw-1, podman (>= 4.9.0), crun | crun-krun, passt, openssh-client
Recommends: ptyxis | gnome-terminal | xdg-terminal-exec
Homepage: https://github.com/krunbox/krunbox
Description: Podman & microVM Sandboxing Engine with GTK4 Console
 krunbox runs AI coding agents and development environments inside lightweight,
 hardware-isolated microVMs on Linux. It combines crun-krun and rootless Podman
 with an outbound egress firewall, an in-guest MCP permission gateway, live port
 forwarding, workspace git guardrails, and a native GTK4 / Libadwaita desktop console.
EOF

cat <<'EOF' > "${DEBIAN_DIR}/postinst"
#!/bin/sh
set -e
if which gtk4-update-icon-cache >/dev/null 2>&1; then
    gtk4-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
elif which gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
if which update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
EOF
chmod 0755 "${DEBIAN_DIR}/postinst"

cat <<'EOF' > "${DEBIAN_DIR}/postrm"
#!/bin/sh
set -e
if which gtk4-update-icon-cache >/dev/null 2>&1; then
    gtk4-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
elif which gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
if which update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
EOF
chmod 0755 "${DEBIAN_DIR}/postrm"

# 8. Build the .deb archive
echo "==> Packaging ${DEB_NAME}..."
dpkg-deb --build --root-owner-group "${STAGING_DIR}" "${DIST_DIR}/${DEB_NAME}"

echo "==> Debian package successfully created at ${DIST_DIR}/${DEB_NAME}"

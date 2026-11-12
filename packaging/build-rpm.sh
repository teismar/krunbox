#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_DIR}"

VERSION=$(grep -m1 '^version = ' pyproject.toml | cut -d'"' -f2)
DIST_DIR="${REPO_DIR}/dist"
mkdir -p "${DIST_DIR}"

# Check if rpmbuild is available locally.
# If not, and docker/podman is available, dispatch into a fedora:45 container.
if ! command -v rpmbuild >/dev/null 2>&1; then
    CONTAINER_RUNTIME=""
    if command -v docker >/dev/null 2>&1; then
        CONTAINER_RUNTIME="docker"
    elif command -v podman >/dev/null 2>&1; then
        CONTAINER_RUNTIME="podman"
    fi

    if [ -n "${CONTAINER_RUNTIME}" ]; then
        echo "==> 'rpmbuild' not found on host. Dispatching build inside Fedora container (${CONTAINER_RUNTIME})..."
        exec ${CONTAINER_RUNTIME} run --rm \
            -v "${REPO_DIR}:/workspace:z" \
            -w /workspace \
            -e "HOST_UID=$(id -u)" \
            -e "HOST_GID=$(id -g)" \
            fedora:45 \
            bash -c "
                set -euo pipefail
                dnf install -y --setopt=install_weak_deps=False \
                    rpm-build python3-devel python3-setuptools python3-wheel \
                    desktop-file-utils libappstream-glib python3-pip
                ./packaging/build-rpm.sh
                if [ -n \"\${HOST_UID:-}\" ]; then
                    chown -R \"\${HOST_UID}:\${HOST_GID}\" /workspace/dist /workspace/build 2>/dev/null || true
                fi
            "
    else
        echo "Error: 'rpmbuild' is not installed and neither Docker nor Podman is available." >&2
        exit 1
    fi
fi

echo "==> Building RPM package for krunbox v${VERSION}..."

# Ensure source tarball exists in dist/
SDIST_FILE="${DIST_DIR}/krunbox-${VERSION}.tar.gz"
if [ ! -f "${SDIST_FILE}" ]; then
    echo "==> Generating source distribution tarball..."
    python3 -m pip install build --quiet || true
    python3 -m build --sdist --outdir "${DIST_DIR}"
fi

RPM_TOPDIR="${REPO_DIR}/build/rpmbuild"
rm -rf "${RPM_TOPDIR}"
mkdir -p "${RPM_TOPDIR}"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

cp "${SDIST_FILE}" "${RPM_TOPDIR}/SOURCES/"
cp "${REPO_DIR}/packaging/krunbox.spec" "${RPM_TOPDIR}/SPECS/"

# Build binary and source RPMs
rpmbuild -bb \
    --define "_topdir ${RPM_TOPDIR}" \
    "${RPM_TOPDIR}/SPECS/krunbox.spec"

# Copy generated RPMs to dist/
mkdir -p "${DIST_DIR}"
find "${RPM_TOPDIR}/RPMS" -type f -name "*.rpm" -exec cp -v {} "${DIST_DIR}/" \;

echo "==> RPM build complete. Packages available in ${DIST_DIR}:"
ls -la "${DIST_DIR}"/*.rpm

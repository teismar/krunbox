"""
Tests for release packaging and changelog extraction logic.
"""

from pathlib import Path
import subprocess
import sys


def test_extract_changelog_v2(tmp_path):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        """# Changelog

## [2.0.0] - 2026-11-12
### Added
- Feature A
- Feature B

## [1.0.0] - 2026-10-31
### Added
- Initial release
""",
        encoding="utf-8",
    )

    script = Path("/workspace/packaging/extract-changelog.py")
    res = subprocess.run(
        [sys.executable, str(script), "v2.0.0", "--changelog", str(changelog)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "### Added" in res.stdout
    assert "- Feature A" in res.stdout
    assert "- Feature B" in res.stdout
    assert "Initial release" not in res.stdout


def test_extract_changelog_v1(tmp_path):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        """# Changelog

## [2.0.0] - 2026-11-12
### Added
- Feature A

## [1.0.0] - 2026-10-31
### Added
- Initial release
""",
        encoding="utf-8",
    )

    script = Path("/workspace/packaging/extract-changelog.py")
    res = subprocess.run(
        [sys.executable, str(script), "1.0.0", "--changelog", str(changelog)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "### Added" in res.stdout
    assert "Initial release" in res.stdout
    assert "Feature A" not in res.stdout


def test_extract_changelog_output_file(tmp_path):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        """## [2.0.0] - 2026-11-12
Release highlights here.
""",
        encoding="utf-8",
    )
    out_file = tmp_path / "RELEASE_NOTES.md"
    script = Path("/workspace/packaging/extract-changelog.py")
    subprocess.run(
        [sys.executable, str(script), "v2.0.0", "--changelog", str(changelog), "--output", str(out_file)],
        check=True,
    )
    assert out_file.is_file()
    assert "Release highlights here." in out_file.read_text(encoding="utf-8")


def test_extract_changelog_fallback(tmp_path):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("## [1.0.0]\nSome notes", encoding="utf-8")
    script = Path("/workspace/packaging/extract-changelog.py")
    res = subprocess.run(
        [sys.executable, str(script), "v9.9.9", "--changelog", str(changelog)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Release v9.9.9" in res.stdout

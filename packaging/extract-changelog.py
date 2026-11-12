#!/usr/bin/env python3
"""
Extract release notes for a specific version from CHANGELOG.md.
Usage:
    python3 packaging/extract-changelog.py <version> [--changelog CHANGELOG.md] [--output RELEASE_NOTES.md]
"""

import argparse
import os
import re
import sys
from pathlib import Path


def extract_changelog(version: str, changelog_path: Path) -> str:
    if not changelog_path.is_file():
        return f"Release {version}"

    text = changelog_path.read_text(encoding="utf-8")

    # Clean version: remove leading 'v'
    clean_version = version.lstrip("v").strip()
    escaped_version = re.escape(clean_version)

    # Match section header like:
    # ## [2.0.0] - 2026-11-12
    # ## 2.0.0 - 2026-11-12
    # ## [v2.0.0]
    pattern = rf"^##\s*\[?v?{escaped_version}\]?(?:\s*-\s*[^\n]*)?$"
    
    lines = text.splitlines()
    in_section = False
    section_lines = []

    for line in lines:
        if re.match(pattern, line.strip(), re.IGNORECASE):
            in_section = True
            continue
        elif in_section and re.match(r"^##\s+.*", line):
            # Reached next section
            break
        elif in_section:
            section_lines.append(line)

    result = "\n".join(section_lines).strip()
    if not result:
        return f"Release {version}\n\nSee CHANGELOG.md for detailed release notes."

    return result


def main():
    parser = argparse.ArgumentParser(description="Extract version section from CHANGELOG.md")
    parser.add_argument("version", help="Version tag to extract (e.g., v2.0.0 or 2.0.0)")
    parser.add_argument("--changelog", "-c", default=None, help="Path to CHANGELOG.md")
    parser.add_argument("--output", "-o", default=None, help="Output file path (default: stdout)")
    args = parser.parse_args()

    changelog_path = None
    if args.changelog:
        changelog_path = Path(args.changelog)
    else:
        # Check standard locations
        for candidate in [Path("CHANGELOG.md"), Path("Changelog.md"), Path("docs/CHANGELOG.md")]:
            if candidate.is_file():
                changelog_path = candidate
                break

    if not changelog_path:
        changelog_path = Path("CHANGELOG.md")

    notes = extract_changelog(args.version, changelog_path)

    if args.output:
        Path(args.output).write_text(notes + "\n", encoding="utf-8")
    else:
        print(notes)


if __name__ == "__main__":
    main()

#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:-dist}"
test -f "$output_dir/artifact-manifest.json"
test -f "$output_dir/SHA256SUMS"
python3 - "$output_dir" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
if root.is_symlink():
    raise SystemExit("release output directory must not be a symlink")
manifest_path = root / "artifact-manifest.json"
sums_path = root / "SHA256SUMS"
if manifest_path.is_symlink() or sums_path.is_symlink():
    raise SystemExit("release metadata must not be a symlink")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
if manifest.get("schema_version") != 1 or not isinstance(manifest.get("files"), list):
    raise SystemExit("invalid release artifact manifest")
entries = manifest["files"]
listed = set()
for entry in entries:
    relative = entry.get("path")
    if not isinstance(relative, str) or not relative or relative.startswith("/") or ".." in Path(relative).parts:
        raise SystemExit("invalid release artifact path")
    if relative in listed:
        raise SystemExit(f"duplicate release artifact path: {relative}")
    listed.add(relative)
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"release artifact is not a regular file: {relative}")
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    actual = f"sha256:{hasher.hexdigest()}"
    if actual != entry.get("digest") or path.stat().st_size != entry.get("bytes"):
        raise SystemExit(f"artifact verification failed: {relative}")
actual_files = set()
for directory, directories, filenames in os.walk(root, followlinks=False):
    directory_path = Path(directory)
    for name in directories:
        path = directory_path / name
        if path.is_symlink():
            raise SystemExit(f"release output contains a symlink: {path}")
    for name in filenames:
        path = directory_path / name
        if path.is_symlink() or not path.is_file():
            raise SystemExit(f"release output contains a non-regular file: {path}")
        actual_files.add(path.relative_to(root).as_posix())
required_files = {"rusty-fuzz", "benchmark", "dependency-inventory.json"}
if listed != required_files:
    raise SystemExit("release manifest does not contain the fixed release file set")
expected_files = listed | {"artifact-manifest.json", "SHA256SUMS"}
if (root / "SIGNATURE").exists():
    expected_files.add("SIGNATURE")
if actual_files != expected_files:
    raise SystemExit("release artifact set does not match the authenticated manifest")
expected_sums = {
    f"{entry['digest'][7:]}  {entry['path']}"
    for entry in entries
}
expected_sums.add(f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  artifact-manifest.json")
sum_entries = []
for line in sums_path.read_text(encoding="utf-8").splitlines():
    parts = line.split("  ", 1)
    if len(parts) != 2 or len(parts[0]) != 64:
        raise SystemExit("invalid SHA256SUMS entry")
    relative = parts[1]
    relative_path = Path(relative)
    if not relative or relative.startswith("/") or ".." in relative_path.parts:
        raise SystemExit("invalid SHA256SUMS path")
    sum_entries.append(f"{parts[0]}  {relative}")
if len(sum_entries) != len(set(sum_entries)):
    raise SystemExit("duplicate SHA256SUMS entry")
actual_sums = set(sum_entries)
if actual_sums != expected_sums:
    raise SystemExit("SHA256SUMS does not match the authenticated artifact set")
PY

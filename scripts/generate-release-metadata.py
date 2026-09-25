#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return f"sha256:{hasher.hexdigest()}"


def regular_files(root: Path) -> list[Path]:
    files = []
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
            files.append(path)
    return sorted(files)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir")
    args = parser.parse_args()
    output_dir = Path(args.output_dir)
    if output_dir.is_symlink():
        raise SystemExit("release output directory must not be a symlink")
    for parent in output_dir.parents:
        if parent.is_symlink():
            raise SystemExit(f"release output parent must not be a symlink: {parent}")
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_dir.is_symlink():
        raise SystemExit("release output directory must not be a symlink")
    for name in ("dependency-inventory.json", "artifact-manifest.json", "SHA256SUMS", "SIGNATURE"):
        if (output_dir / name).is_symlink():
            raise SystemExit(f"release metadata file must not be a symlink: {name}")
    metadata = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        check=True,
        capture_output=True,
        text=True,
    )
    document = json.loads(metadata.stdout)
    packages = sorted(
        (
            {
                "name": package["name"],
                "version": package["version"],
                "source": package.get("source"),
            }
            for package in document.get("packages", [])
        ),
        key=lambda item: (item["name"], item["version"], item.get("source") or ""),
    )
    inventory = {
        "schema_version": 1,
        "format": "cargo-metadata-dependency-inventory",
        "packages": packages,
    }
    (output_dir / "dependency-inventory.json").write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    allowed_files = {
        "rusty-fuzz",
        "benchmark",
        "dependency-inventory.json",
        "artifact-manifest.json",
        "SHA256SUMS",
        "SIGNATURE",
    }
    for path in regular_files(output_dir):
        relative = path.relative_to(output_dir).as_posix()
        if relative not in allowed_files:
            raise SystemExit(f"unexpected release output file: {relative}")
    excluded = {"artifact-manifest.json", "SHA256SUMS", "SIGNATURE"}
    files = []
    for path in regular_files(output_dir):
        if path.name in excluded:
            continue
        relative = path.relative_to(output_dir).as_posix()
        files.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "digest": digest(path),
            }
        )
    manifest = {"schema_version": 1, "files": files}
    (output_dir / "artifact-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    sums = []
    for path in regular_files(output_dir):
        if path.name == "SHA256SUMS":
            continue
        relative = path.relative_to(output_dir).as_posix()
        sums.append(f"{digest(path)[7:]}  {relative}")
    (output_dir / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

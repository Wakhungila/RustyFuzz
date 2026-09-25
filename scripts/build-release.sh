#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:-dist}"
if [ "${RUSTYFUZZ_REQUIRE_SIGNING:-0}" != "1" ] && [ "${RUSTYFUZZ_ALLOW_UNSIGNED_RELEASE:-0}" != "1" ]; then
  printf '%s\n' 'release signing is required; set RUSTYFUZZ_ALLOW_UNSIGNED_RELEASE=1 only for unsigned CI checks' >&2
  exit 1
fi

staging_dir="$(python3 - "$output_dir" <<'PY'
import os
import sys
import tempfile
from pathlib import Path

root = Path(sys.argv[1]).absolute()
if root.exists() or root.is_symlink():
    raise SystemExit("release output path must not already exist")

current = Path(root.anchor)
for part in root.parent.parts[1:] if root.anchor else root.parent.parts:
    current /= part
    if current.is_symlink():
        raise SystemExit(f"release parent contains a symlink: {current}")
    if current.exists():
        if not current.is_dir():
            raise SystemExit(f"release parent is not a directory: {current}")
    else:
        current.mkdir()

staging = Path(tempfile.mkdtemp(prefix=".rustyfuzz-release-", dir=root.parent))
os.chmod(staging, 0o700)
print(staging)
PY
)"

cleanup() {
  if [ -n "${staging_dir:-}" ] && [ -d "$staging_dir" ]; then
    rm -rf -- "$staging_dir"
  fi
}
trap cleanup EXIT

cargo build --release --locked --bin rusty-fuzz --bin benchmark
install -m 0755 target/release/rusty-fuzz "$staging_dir/rusty-fuzz"
install -m 0755 target/release/benchmark "$staging_dir/benchmark"
python3 scripts/generate-release-metadata.py "$staging_dir"
./scripts/verify-release-artifacts.sh "$staging_dir"
./scripts/verify-release-signature.sh "$staging_dir"
python3 - "$staging_dir" "$output_dir" <<'PY'
import ctypes
import os
import platform
import sys
from pathlib import Path

system = platform.system()
if system not in {"Linux", "Darwin"}:
    raise SystemExit("race-resistant release publication requires Linux or macOS")
staging = Path(sys.argv[1]).absolute()
output = Path(sys.argv[2]).absolute()
libc = ctypes.CDLL(None, use_errno=True)
if system == "Linux":
    publish = libc.renameat2
    at_fdcwd = -100
    exclusive_flag = 1
else:
    publish = libc.renameatx_np
    at_fdcwd = -2
    exclusive_flag = 0x00000004
publish.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
publish.restype = ctypes.c_int
if publish(at_fdcwd, os.fsencode(staging), at_fdcwd, os.fsencode(output), exclusive_flag) != 0:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error), str(output))
dir_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(dir_fd)
finally:
    os.close(dir_fd)
PY
trap - EXIT

#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:-dist}"
mkdir -p "$output_dir"

cargo build --release --locked --bin rusty-fuzz --bin benchmark
cp target/release/rusty-fuzz target/release/benchmark "$output_dir/"

sha256sum \
  "$output_dir/rusty-fuzz" \
  "$output_dir/benchmark" \
  | tee "$output_dir/SHA256SUMS"
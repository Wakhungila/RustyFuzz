#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:-dist}"
if [ "${RUSTYFUZZ_REQUIRE_SIGNING:-0}" != "1" ]; then
  exit 0
fi
signature_file="${RUSTYFUZZ_SIGNATURE_FILE:-$output_dir/SIGNATURE}"
if [ ! -f "$signature_file" ]; then
  printf '%s\n' 'signing required but signature file is missing' >&2
  exit 1
fi
if command -v cosign >/dev/null 2>&1 && [ -n "${RUSTYFUZZ_COSIGN_PUBLIC_KEY:-}" ]; then
  cosign verify-blob --key "$RUSTYFUZZ_COSIGN_PUBLIC_KEY" --signature "$signature_file" "$output_dir/artifact-manifest.json"
  exit 0
fi
if command -v gpg >/dev/null 2>&1 && [ -n "${RUSTYFUZZ_GPG_KEY_ID:-}" ]; then
  key_id="$RUSTYFUZZ_GPG_KEY_ID"
  if ! [[ "$key_id" =~ ^[0-9A-Fa-f]{40}$ ]]; then
    printf '%s\n' 'RUSTYFUZZ_GPG_KEY_ID must be a full 40-character fingerprint' >&2
    exit 1
  fi
  key_id_upper=${key_id^^}
  status=$(gpg --status-fd 1 --verify "$signature_file" "$output_dir/artifact-manifest.json" 2>/dev/null) || {
    printf '%s\n' 'GPG signature verification failed' >&2
    exit 1
  }
  matched=0
  while read -r marker status_name fingerprint _; do
    if [ "$marker" = "[GNUPG:]" ] && [ "$status_name" = "VALIDSIG" ]; then
      if [ "${fingerprint^^}" = "$key_id_upper" ]; then
        matched=1
      fi
    fi
  done <<<"$status"
  if [ "$matched" -ne 1 ]; then
    printf '%s\n' 'GPG signature was not made by RUSTYFUZZ_GPG_KEY_ID' >&2
    exit 1
  fi
  exit 0
fi
printf '%s\n' 'signing required but no supported verifier/key is configured' >&2
exit 1

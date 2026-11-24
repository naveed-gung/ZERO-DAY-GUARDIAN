#!/usr/bin/env bash
set -euo pipefail

destination="${1:?installation directory required}"
version="0.12.0"
case "$(uname -m)" in
  x86_64|aarch64) architecture="$(uname -m)" ;;
  *) echo "Unsupported bpf-linker architecture: $(uname -m)" >&2; exit 1 ;;
esac

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
asset="bpf-linker-$architecture-unknown-linux-musl.tar.zst"
curl --fail --silent --show-error --location --retry 3   "https://github.com/aya-rs/bpf-linker/releases/download/v$version/$asset"   --output "$scratch/$asset"
tar --extract --zstd --file "$scratch/$asset" --directory "$scratch"
install -D -m 0755 "$scratch/bpf-linker" "$destination/bpf-linker"
"$destination/bpf-linker" --version

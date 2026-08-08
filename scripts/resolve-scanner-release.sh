#!/usr/bin/env bash
set -euo pipefail

scanner="${1:-}"
runner_arch="${RUNNER_ARCH:-}"

case "$scanner:$runner_arch" in
  gitleaks:X64)
    archive_name="gitleaks_8.30.1_linux_x64.tar.gz"
    archive_sha256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
    ;;
  gitleaks:ARM64)
    archive_name="gitleaks_8.30.1_linux_arm64.tar.gz"
    archive_sha256="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
    ;;
  *)
    printf 'Unsupported scanner or RUNNER_ARCH: scanner=%s RUNNER_ARCH=%s\n' \
      "${scanner:-<unset>}" "${runner_arch:-<unset>}" >&2
    exit 64
    ;;
esac

printf '%s\t%s\n' "$archive_name" "$archive_sha256"

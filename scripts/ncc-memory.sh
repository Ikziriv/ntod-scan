#!/usr/bin/env bash
# Run `ecc memory` against this repo's .ncc vault regardless of cwd —
# ECC_MEMORY_PROJECT_ROOT resolves relative to cwd and silently misses
# the vault from subdirectories.
set -e
cd "$(git rev-parse --show-toplevel)"
exec ecc memory "$@"

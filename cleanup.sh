#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "Removing disposable build and runtime artifacts..."

rm -rf .venv __pycache__ "${ROOT}/__pycache__"
rm -f .DS_Store
#rm -f demo/libvuln_kem.so libmlkem768.so
rm -f _ctshim*.so
rm -rf crashes/* crashes_poly/*

echo "Cleanup complete."

#!/usr/bin/env bash
# Remove everything generated/regenerable in this tree: Cargo's build output,
# fetched PQClean source, built .so files, and fuzzer crash artifacts.
# Nothing this script touches is source -- see README.md/Makefile for how
# each gets rebuilt (`cargo build`, `make mock`, `make pqclean`).
set -euo pipefail
cd "$(dirname "$0")"

make clean
rm -rf crashes/* target/*

echo "cleaned: target/, crashes/, examples/libmock_pqc.so, libmlkem768_pqclean.so, libmldsa65_pqclean.so, .pqclean-src/"
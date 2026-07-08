#!/usr/bin/env bash
# build_demo.sh -- compile the intentionally-flawed demo KEM used by
# `latticescope selftest`. Produces libvuln_kem.so next to this script.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
CC="${CC:-cc}"
OUT="${HERE}/libvuln_kem.so"
ROOT_LINK="${ROOT}/libmlkem768.so"

# -O2 is deliberate: it mirrors how a real build would be optimised. The planted
# timing leak here is explicit (a data-dependent loop), so it survives the
# optimiser regardless -- the point is to exercise the *detector*, not to rely
# on a specific compiler introducing the leak for us.
"${CC}" -O2 -fPIC -shared -Wall "${HERE}/vuln_kem.c" -o "${OUT}"
ln -sf "${OUT}" "${ROOT_LINK}"
echo "built ${OUT}"
echo "link  ${ROOT_LINK}"
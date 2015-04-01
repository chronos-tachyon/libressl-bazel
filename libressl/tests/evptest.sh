#!/bin/sh
set -eu
bin="${TEST_SRCDIR}/libressl/tests/evptest"
data="${TEST_SRCDIR}/libressl/tests/evptests.txt"
if [ -e "${bin}.exe" ]; then
	bin="${bin}.exe"
fi
"$bin" "$data"

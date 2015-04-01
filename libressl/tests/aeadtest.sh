#!/bin/sh
set -eu
bin="${TEST_SRCDIR}/libressl/tests/aeadtest"
data="${TEST_SRCDIR}/libressl/tests/aeadtests.txt"
if [ -e "${bin}.exe" ]; then
	bin="${bin}.exe"
fi
"$bin" "$data"

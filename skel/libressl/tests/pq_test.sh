#!/bin/sh
set -eu
bin="${TEST_SRCDIR}/libressl/tests/pq_test"
data="${TEST_SRCDIR}/libressl/tests/pq_expected.txt"
if [ -e "${bin}.exe" ]; then
	bin="${bin}.exe"
fi
"$bin" | diff -b "$data" -

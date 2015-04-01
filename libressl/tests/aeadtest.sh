#!/bin/sh
set -eu
DIR="${TEST_SRCDIR}/libressl/tests"
TEST="${DIR}/aeadtest"
DATA="${DIR}/aeadtests.txt"
if [ -e "${TEST}.exe" ]; then
	TEST="${TEST}.exe"
fi
"$TEST" "$DATA"

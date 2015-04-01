#!/bin/sh
set -eu
DIR="${TEST_SRCDIR}/libressl/tests"
TEST="${DIR}/arc4randomforktest"
"$TEST"
"$TEST" -b
"$TEST" -p
"$TEST" -bp

#!/bin/sh
set -eu
bin="${TEST_SRCDIR}/libressl/tests/arc4random-fork"
if [ -e "${bin}.exe" ]; then
	bin="${bin}.exe"
fi
"$bin"
"$bin" -b
"$bin" -p
"$bin" -bp

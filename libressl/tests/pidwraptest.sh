#!/bin/sh
set -eu
bin="${TEST_SRCDIR}/libressl/tests/pidwraptest"
tmpdir="${TMPDIR:-${TEMP:-/tmp}}"
out="$(mktemp "${tmpdir}/pidwraptest.$$.XXXXXXXX")"
if [ -e "${bin}.exe" ]; then
	bin="${bin}.exe"
fi
"$bin" > "$out"
while read a b; do
	if [ "$a" = "$b" ]; then
		echo "FAIL: $a = $b"
		exit 2
	else
		echo "PASS: $a != $b"
	fi
done < "$out"

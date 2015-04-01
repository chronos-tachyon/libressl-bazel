#!/bin/sh
set -eu
ssltest_bin="${TEST_SRCDIR}/libressl/tests/ssltest"
openssl_bin="${TEST_SRCDIR}/libressl/apps/openssl"
server_pem="${TEST_SRCDIR}/libressl/tests/server.pem"
ca_pem="${TEST_SRCDIR}/libressl/tests/ca.pem"
if [ -e "${ssltest_bin}.exe" ]; then
	ssltest_bin="${ssltest_bin}.exe"
fi
if [ -e "${openssl_bin}.exe" ]; then
	openssl_bin="${openssl_bin}.exe"
fi

key="$server_pem"
cert="$server_pem"
cacert="$ca_pem"

ssltest() {
  "$ssltest_bin" \
    -key "$key" -cert "$cert" \
    -c_key "$key" -c_cert "$cert" \
    "$@"
}
ssltest_CA() {
  ssltest -CAfile "$cacert" "$@"
}
openssl() {
  "$openssl_bin" "$@"
}

if openssl x509 -in "$cert" -text -noout | fgrep 'DSA Public Key' >/dev/null; then
  dsa_cert=YES
else
  dsa_cert=NO
fi

#############################################################################

echo 'test sslv3'
ssltest -ssl3 || exit 1

echo 'test sslv3 with server authentication'
ssltest_CA -ssl3 -server_auth || exit 1

echo 'test sslv3 with client authentication'
ssltest_CA -ssl3 -client_auth || exit 1

echo 'test sslv3 with both client and server authentication'
ssltest_CA -ssl3 -server_auth -client_auth || exit 1

echo 'test sslv2/sslv3'
ssltest || exit 1

echo 'test sslv2/sslv3 with server authentication'
ssltest_CA -server_auth || exit 1

echo 'test sslv2/sslv3 with client authentication'
ssltest_CA -client_auth || exit 1

echo 'test sslv2/sslv3 with both client and server authentication'
ssltest_CA -server_auth -client_auth || exit 1

echo 'test sslv3 via BIO pair'
ssltest -bio_pair -ssl3 || exit 1

echo 'test sslv3 with server authentication via BIO pair'
ssltest_CA -bio_pair -ssl3 -server_auth || exit 1

echo 'test sslv3 with client authentication via BIO pair'
ssltest_CA -bio_pair -ssl3 -client_auth || exit 1

echo 'test sslv3 with both client and server authentication via BIO pair'
ssltest_CA -bio_pair -ssl3 -server_auth -client_auth || exit 1

echo 'test sslv2/sslv3 via BIO pair'
ssltest || exit 1

if [ $dsa_cert = NO ]; then
  echo 'test sslv2/sslv3 w/o (EC)DHE via BIO pair'
  ssltest -bio_pair -no_dhe -no_ecdhe || exit 1
fi

echo 'test sslv2/sslv3 with 1024bit DHE via BIO pair'
ssltest -bio_pair -dhe1024dsa -v || exit 1

echo 'test sslv2/sslv3 with server authentication'
ssltest_CA -bio_pair -server_auth || exit 1

echo 'test sslv2/sslv3 with client authentication via BIO pair'
ssltest_CA -bio_pair -client_auth || exit 1

echo 'test sslv2/sslv3 with both client and server authentication via BIO pair'
ssltest_CA -bio_pair -server_auth -client_auth || exit 1

echo 'test sslv2/sslv3 with both client and server authentication via BIO pair and app verify'
ssltest_CA -bio_pair -server_auth -client_auth -app_verify || exit 1

echo 'Testing ciphersuites'
for protocol in SSLv3 TLSv1.2; do
  echo "Testing ciphersuites for ${protocol}"
  for cipher in `openssl ciphers "${protocol}+aRSA" | tr ':' ' '`; do
    echo "Testing ${cipher}"
    prot=''
    if [ "$protocol" = "SSLv3" ] ; then
      prot='-ssl3'
    fi
    ssltest -cipher "$cipher" $prot
    if [ $? -ne 0 ] ; then
      echo "Failed ${cipher}"
      exit 1
    fi
  done
done

#############################################################################

if openssl no-dh; then
  echo 'skipping anonymous DH tests'
else
  echo 'test tls1 with 1024bit anonymous DH, multiple handshakes'
  ssltest -v -bio_pair -tls1 -cipher ADH -dhe1024dsa -num 10 -f -time || exit 1
fi

#if openssl no-rsa; then
#  echo 'skipping RSA tests'
#else
#  echo 'test tls1 with 1024bit RSA, no (EC)DHE, multiple handshakes'
#  ./ssltest -v -bio_pair -tls1 -cert ../apps/server2.pem -no_dhe -no_ecdhe -num 10 -f -time || exit 1
#
#  if openssl no-dh; then
#    echo 'skipping RSA+DHE tests'
#  else
#    echo 'test tls1 with 1024bit RSA, 1024bit DHE, multiple handshakes'
#    ./ssltest -v -bio_pair -tls1 -cert ../apps/server2.pem -dhe1024dsa -num 10 -f -time || exit 1
#  fi
#fi

#
# DTLS tests
#

echo 'test dtlsv1'
ssltest -dtls1 || exit 1

echo 'test dtlsv1 with server authentication'
ssltest_CA -dtls1 -server_auth || exit 1

echo 'test dtlsv1 with client authentication'
ssltest_CA -dtls1 -client_auth || exit 1

echo 'test dtlsv1 with both client and server authentication'
ssltest_CA -dtls1 -server_auth -client_auth || exit 1

echo 'Testing DTLS ciphersuites'
for protocol in SSLv3; do
  echo "Testing ciphersuites for ${protocol}"
  for cipher in `openssl ciphers "RSA+${protocol}" | tr ':' '\n' |
    grep -v RC4`; do
    echo "Testing ${cipher}"
    ssltest -cipher $cipher -dtls1
    if [ $? -ne 0 ] ; then
      echo "Failed ${cipher}"
      exit 1
    fi
  done
done

#
# Next Protocol Negotiation tests
#
echo 'Testing NPN...'
ssltest -bio_pair -tls1 -npn_client || exit 1
ssltest -bio_pair -tls1 -npn_server || exit 1
ssltest -bio_pair -tls1 -npn_server_reject || exit 1
ssltest -bio_pair -tls1 -npn_client -npn_server_reject || exit 1
ssltest -bio_pair -tls1 -npn_client -npn_server || exit 1
ssltest -bio_pair -tls1 -npn_client -npn_server -num 2 || exit 1
ssltest -bio_pair -tls1 -npn_client -npn_server -num 2 -reuse || exit 1

#
# ALPN tests
#
echo 'Testing ALPN...'
ssltest -bio_pair -tls1 -alpn_client foo -alpn_server bar || exit 1
ssltest -bio_pair -tls1 -alpn_client foo -alpn_server foo \
  -alpn_expected foo || exit 1
ssltest -bio_pair -tls1 -alpn_client foo,bar -alpn_server foo \
  -alpn_expected foo || exit 1
ssltest -bio_pair -tls1 -alpn_client bar,foo -alpn_server foo \
  -alpn_expected foo || exit 1
ssltest -bio_pair -tls1 -alpn_client bar,foo -alpn_server foo,bar \
  -alpn_expected foo || exit 1
ssltest -bio_pair -tls1 -alpn_client bar,foo -alpn_server bar,foo \
  -alpn_expected bar || exit 1
ssltest -bio_pair -tls1 -alpn_client foo,bar -alpn_server bar,foo \
  -alpn_expected bar || exit 1
ssltest -bio_pair -tls1 -alpn_client baz -alpn_server bar,foo || exit 1

# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

filegroup(
    name = "include",
    srcs = [
      ":compat",
      ":libcrypto",
      ":libssl",
      ":libtls",
    ],
    visibility = ["//libressl:__pkg__"],
)

filegroup(
    name = "compat",
    srcs = glob([
      "arpa/inet.h",
      "machine/endian.h",
      "netinet/in.h",
      "netinet/tcp.h",
      "sys/ioctl.h",
      "sys/mman.h",
      "sys/select.h",
      "sys/socket.h",
      "sys/times.h",
      "sys/types.h",
      "sys/uio.h",
      "arc4random*.h",
      "chacha_private.h",
      "err.h",
      "netdb.h",
      "poll.h",
      "stdio.h",
      "stdlib.h",
      "string.h",
      "syslog.h",
      "unistd.h",
      "win32netcompat.h",
    ]),
    visibility = ["//libressl:__subpackages__"],
)

filegroup(
    name = "libcrypto",
    srcs = ['openssl/aes.h', 'openssl/asn1.h', 'openssl/asn1_mac.h', 'openssl/asn1t.h', 'openssl/bio.h', 'openssl/blowfish.h', 'openssl/bn.h', 'openssl/buffer.h', 'openssl/camellia.h', 'openssl/cast.h', 'openssl/chacha.h', 'openssl/cmac.h', 'openssl/cms.h', 'openssl/comp.h', 'openssl/conf.h', 'openssl/conf_api.h', 'openssl/crypto.h', 'openssl/des.h', 'openssl/dh.h', 'openssl/dsa.h', 'openssl/dso.h', 'openssl/e_os2.h', 'openssl/ec.h', 'openssl/ecdh.h', 'openssl/ecdsa.h', 'openssl/engine.h', 'openssl/err.h', 'openssl/evp.h', 'openssl/gost.h', 'openssl/hmac.h', 'openssl/idea.h', 'openssl/krb5_asn.h', 'openssl/lhash.h', 'openssl/md4.h', 'openssl/md5.h', 'openssl/mdc2.h', 'openssl/modes.h', 'openssl/obj_mac.h', 'openssl/objects.h', 'openssl/ocsp.h', 'openssl/opensslconf.h', 'openssl/opensslfeatures.h', 'openssl/opensslv.h', 'openssl/ossl_typ.h', 'openssl/pem2.h', 'openssl/pem.h', 'openssl/pkcs7.h', 'openssl/pkcs12.h', 'openssl/poly1305.h', 'openssl/rand.h', 'openssl/rc2.h', 'openssl/rc4.h', 'openssl/ripemd.h', 'openssl/rsa.h', 'openssl/safestack.h', 'openssl/sha.h', 'openssl/stack.h', 'openssl/ts.h', 'openssl/txt_db.h', 'openssl/ui.h', 'openssl/ui_compat.h', 'openssl/whrlpool.h', 'openssl/x509.h', 'openssl/x509_vfy.h', 'openssl/x509v3.h'],
    visibility = ["//libressl/crypto:__pkg__"],
)

filegroup(
    name = "libssl",
    srcs = ['openssl/dtls1.h', 'openssl/srtp.h', 'openssl/ssl2.h', 'openssl/ssl3.h', 'openssl/ssl23.h', 'openssl/ssl.h', 'openssl/tls1.h'],
    visibility = ["//libressl/ssl:__pkg__"],
)

filegroup(
    name = "libtls",
    srcs = ['pqueue.h', 'tls.h'],
    visibility = ["//libressl/tls:__pkg__"],
)

cc_library(
    name = "pqueue",
    hdrs = ["pqueue.h"],
    visibility = ["//libressl/ssl:__pkg__"],
)

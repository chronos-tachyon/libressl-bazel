# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

cc_library(
    name = "openssl",
    hdrs = [
      ":libcrypto_headers",
      ":libssl_headers",
    ],
    deps = [
      "//libressl:libcrypto",
      "//libressl:libssl",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    hdrs = [
      ":libcrypto_headers",
      ":libssl_headers",
    ],
    visibility = ["//visibility:public"],
)

filegroup(
    name = "libcrypto_headers",
    srcs = ['aes.h', 'asn1.h', 'asn1_mac.h', 'asn1t.h', 'bio.h', 'blowfish.h', 'bn.h', 'buffer.h', 'camellia.h', 'cast.h', 'chacha.h', 'cmac.h', 'cms.h', 'comp.h', 'conf.h', 'conf_api.h', 'crypto.h', 'des.h', 'dh.h', 'dsa.h', 'dso.h', 'e_os2.h', 'ec.h', 'ecdh.h', 'ecdsa.h', 'engine.h', 'err.h', 'evp.h', 'gost.h', 'hmac.h', 'idea.h', 'krb5_asn.h', 'lhash.h', 'md4.h', 'md5.h', 'mdc2.h', 'modes.h', 'obj_mac.h', 'objects.h', 'ocsp.h', 'opensslconf.h', 'opensslfeatures.h', 'opensslv.h', 'ossl_typ.h', 'pem2.h', 'pem.h', 'pkcs7.h', 'pkcs12.h', 'poly1305.h', 'rand.h', 'rc2.h', 'rc4.h', 'ripemd.h', 'rsa.h', 'safestack.h', 'sha.h', 'stack.h', 'ts.h', 'txt_db.h', 'ui.h', 'ui_compat.h', 'whrlpool.h', 'x509.h', 'x509_vfy.h', 'x509v3.h'],
    visibility = ["//libressl:__subpackages__"],
)

filegroup(
    name = "libssl_headers",
    srcs = ['dtls1.h', 'srtp.h', 'ssl2.h', 'ssl3.h', 'ssl23.h', 'ssl.h', 'tls1.h'],
    visibility = ["//libressl:__subpackages__"],
)

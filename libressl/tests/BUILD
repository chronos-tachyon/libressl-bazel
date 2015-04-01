# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

cc_binary(
    name = "aeadtest",
    srcs = ["aeadtest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
    testonly = 1,
)
sh_test(
    name = "aeadtest_test",
    timeout = "short",
    srcs = ["aeadtest.sh"],
    data = ["aeadtest", "aeadtests.txt"],
)

cc_test(
    name = "aeswrap_test",
    size = "small",
    srcs = ["aes_wrap.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_binary(
    name = "arc4random-fork",
    srcs = ["arc4random-fork.c"],
    deps = [
      "//libressl/crypto",
    ],
    copts = ["-include", "stdint.h"],
    testonly = 1,
)
sh_test(
    name = "arc4random-fork_test",
    timeout = "short",
    srcs = ["arc4randomforktest.sh"],
    data = ["arc4random-fork"],
)

cc_test(
    name = "asn1_test",
    size = "small",
    srcs = ["asn1test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto", "//libressl/ssl"],
)

cc_test(
    name = "base64_test",
    size = "small",
    srcs = ["base64test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "bf_test",
    size = "small",
    srcs = ["bftest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "bio_test",
    size = "small",
    tags = ["manual", "failing"],
    srcs = ["biotest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "bn_test",
    size = "small",
    srcs = ["bntest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "bytestring_test",
    size = "small",
    srcs = ["bytestringtest.c"],
    copts = [
      "-Ilibressl/include",
      "-Ilibressl/ssl",
    ],
    deps = [
      "//libressl/ssl",
      "//libressl/ssl:internal_bytestring",
    ],
)

cc_test(
    name = "cast_test",
    size = "small",
    srcs = ["casttest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "chacha_test",
    size = "small",
    srcs = ["chachatest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "ciphers_test",
    size = "small",
    srcs = ["cipherstest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto", "//libressl/ssl"],
)

cc_test(
    name = "cts128_test",
    size = "small",
    srcs = ["cts128test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "des_test",
    size = "small",
    srcs = ["destest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "dh_test",
    size = "small",
    srcs = ["dhtest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "dsa_test",
    size = "small",
    srcs = ["dsatest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "ecdh_test",
    size = "small",
    srcs = ["ecdhtest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "ecdsa_test",
    size = "small",
    srcs = ["ecdsatest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "ec_test",
    size = "small",
    srcs = ["ectest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "engine_test",
    size = "small",
    srcs = ["enginetest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_binary(
    name = "evptest",
    srcs = ["evptest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
    testonly = 1,
)
sh_test(
    name = "evptest_test",
    timeout = "short",
    srcs = ["evptest.sh"],
    data = ["evptest", "evptests.txt"],
)

cc_test(
    name = "explicit_bzero_test",
    size = "small",
    srcs = ["explicit_bzero.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "exp_test",
    size = "small",
    srcs = ["exptest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "gcm128_test",
    size = "small",
    srcs = ["gcm128test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "gost2814789_test",
    size = "small",
    srcs = ["gost2814789t.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "hmac_test",
    size = "small",
    srcs = ["hmactest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "idea_test",
    size = "small",
    srcs = ["ideatest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "ige_test",
    size = "small",
    srcs = ["igetest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "md4_test",
    size = "small",
    srcs = ["md4test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "md5_test",
    size = "small",
    srcs = ["md5test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "mdc2_test",
    size = "small",
    srcs = ["mdc2test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "mont_test",
    size = "small",
    srcs = ["mont.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "pbkdf2_test",
    size = "small",
    srcs = ["pbkdf2.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_binary(
    name = "pidwraptest",
    srcs = ["pidwraptest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
    testonly = 1,
)
sh_test(
    name = "pidwraptest_test",
    timeout = "short",
    srcs = ["pidwraptest.sh"],
    data = ["pidwraptest"],
)

cc_test(
    name = "pkcs7_test",
    size = "small",
    srcs = ["pkcs7test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "poly1305_test",
    size = "small",
    srcs = ["poly1305test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_binary(
    name = "pq_test",
    srcs = ["pq_test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl"],
    testonly = 1,
)
sh_test(
    name = "pq_test_test",
    timeout = "short",
    srcs = ["pq_test.sh"],
    data = ["pq_test", "pq_expected.txt"],
)

cc_test(
    name = "rand_test",
    size = "small",
    srcs = ["randtest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "rc2_test",
    size = "small",
    srcs = ["rc2test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "rc4_test",
    size = "small",
    srcs = ["rc4test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "rmd_test",
    size = "small",
    srcs = ["rmdtest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "sha_test",
    size = "small",
    srcs = ["shatest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "sha1_test",
    size = "small",
    srcs = ["sha1test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "sha256_test",
    size = "small",
    srcs = ["sha256test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "sha512_test",
    size = "small",
    srcs = ["sha512test.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_binary(
    name = "ssltest",
    srcs = ["ssltest.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl"],
    testonly = 1,
)
sh_test(
    name = "ssltest_test",
    timeout = "short",
    srcs = ["ssltest.sh"],
    data = [
      "ssltest",
      "server.pem",
      "ca.pem",
      "//libressl/apps:openssl",
    ],
)

cc_test(
    name = "timingsafe_test",
    size = "small",
    srcs = ["timingsafe.c"],
    copts = ["-Ilibressl/include"],
    deps = ["//libressl/crypto"],
)

cc_test(
    name = "utf8_test",
    size = "small",
    srcs = ["utf8test.c"],
    copts = [
      "-Ilibressl/include",
      "-Ilibressl/crypto/asn1",
    ],
    deps = [
      "//libressl/crypto",
      "//libressl/crypto:internal_asn1",
    ],
)

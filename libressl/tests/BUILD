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
    name = "regress-aeadtest",
    timeout = "short",
    srcs = ["aeadtest.sh"],
    data = ["aeadtest", "aeadtests.txt"],
)

cc_binary(
    name = "arc4randomforktest",
    srcs = ["arc4randomforktest.c"],
    deps = [
      "//libressl/crypto",
    ],
    copts = ["-include", "stdint.h"],
    testonly = 1,
)
sh_test(
    name = "regress-arc4random-fork",
    timeout = "short",
    srcs = ["arc4randomforktest.sh"],
    data = ["arc4randomforktest"],
)

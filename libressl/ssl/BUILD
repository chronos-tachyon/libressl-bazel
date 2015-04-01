# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

cc_library(
    name = "ssl",
    hdrs = ["//libressl/include:libssl"],
    srcs = glob(["**/*.c", "**/*.h"]),
    copts = [
      "-Ilibressl/include",
      "-Ilibressl/include/openssl",
      "-DLIBRESSL_INTERNAL",
    ],
    deps = [
      ":headers",
      "//libressl/include:pqueue",
      "//libressl/crypto",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    hdrs = ["//libressl/include:libssl"],
    includes = ["libressl/include"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "internal_bytestring",
    hdrs = ["bytestring.h"],
    visibility = ["//libressl/tests:__pkg__"],
)

# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

cc_library(
    name = "tls",
    hdrs = ["//libressl/include:libtls"],
    srcs = glob(["*.c", "*.h"]),
    copts = [
      "-Ilibressl/include",
      "-DLIBRESSL_INTERNAL",
    ],
    deps = [
      ":headers",
      "//libressl/crypto",
      "//libressl/ssl",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    hdrs = ["//libressl/include:libtls"],
    includes = ["libressl/include"],
    visibility = ["//visibility:public"],
)

# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

cc_library(
    name = "tls",
    hdrs = ["//libressl:libtls_headers"],
    srcs = [
      "tls.c",
      "tls_client.c",
      "tls_config.c",
      "tls_server.c",
      "tls_util.c",
      "tls_verify.c",
      "tls_internal.h",
    ],
    deps = [
      "//libressl:libcrypto",
      "//libressl:libssl",
    ],
    copts = ["-include", "stdint.h"],
    visibility = ["//libressl:__pkg__"],
)

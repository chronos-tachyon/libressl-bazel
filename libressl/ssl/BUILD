# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

cc_library(
    name = "ssl",
    hdrs = [
      "//libressl:libtls_headers",
      "//openssl:libssl_headers",
    ],
    srcs = glob([
      "**/*.c",
      "**/*.h",
    ]),
    deps = [
      "//libressl:libcrypto",
      "//libressl/compat",
    ],
    copts = ["-Ilibressl/compat"],
    visibility = ["//libressl:__pkg__"],
)

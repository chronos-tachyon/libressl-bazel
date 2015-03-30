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
    srcs = {{libcrypto_headers}},
    visibility = ["//libressl:__subpackages__"],
)

filegroup(
    name = "libssl_headers",
    srcs = {{libssl_headers}},
    visibility = ["//libressl:__subpackages__"],
)

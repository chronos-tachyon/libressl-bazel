# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

cc_library(
    name = "libressl",
    hdrs = [
      ":libtls_headers",
      "//openssl:libcrypto_headers",
      "//openssl:libssl_headers",
    ],
    deps = [
      ":libcrypto",
      ":libssl",
      ":libtls",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    hdrs = [
      ":libtls_headers",
      "//openssl:libcrypto_headers",
      "//openssl:libssl_headers",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "libcrypto",
    hdrs = ["//openssl:libcrypto_headers"],
    deps = ["//libressl/crypto"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "libssl",
    hdrs = ["//openssl:libssl_headers"],
    deps = ["//libressl/ssl"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "libtls",
    hdrs = [":libtls_headers"],
    deps = ["//libressl/tls"],
    visibility = ["//visibility:public"],
)

filegroup(
    name = "libtls_headers",
    srcs = {{libtls_headers}},
    visibility = ["//libressl:__subpackages__"],
)

config_setting(
    name = "asm-i386-elf",
    values = {"cpu": "piii", "define": "ABI=elf"},
    visibility = ["//libressl:__subpackages__"],
)
config_setting(
    name = "asm-i386-macosx",
    values = {"cpu": "piii", "define": "ABI=macosx"},
    visibility = ["//libressl:__subpackages__"],
)

config_setting(
    name = "asm-amd64-elf",
    values = {"cpu": "k8", "define": "ABI=elf"},
    visibility = ["//libressl:__subpackages__"],
)
config_setting(
    name = "asm-amd64-macosx",
    values = {"cpu": "k8", "define": "ABI=macosx"},
    visibility = ["//libressl:__subpackages__"],
)

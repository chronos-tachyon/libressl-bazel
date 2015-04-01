# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

cc_library(
    name = "libressl",
    hdrs = ["//libressl/include"],
    includes = ["libressl/include"],
    deps = [
      "//libressl/crypto",
      "//libressl/ssl",
      "//libressl/tls",
    ],
    visibility = ["//visibility:public"],
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

# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

cc_binary(
    name = "openssl",
    srcs = glob(["*.c", "*.h"], exclude=["certhash_disabled.c"]),
    deps = [
      "//libressl:libcrypto",
      "//libressl:libssl",
      "//libressl:libtls",
    ],
    copts = ["-DLIBRESSL_INTERNAL"],
    visibility = ["//libressl:__pkg__"],
)

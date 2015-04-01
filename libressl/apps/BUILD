# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

cc_binary(
    name = "openssl",
    srcs = glob(
      ["*.c", "*.h"],
      exclude=[
        "cms.c",
        "certhash_disabled.c",
      ],
    ),
    copts = [
      "-Ilibressl/include",
      "-DHAVE_POLL",
      "-DLIBRESSL_INTERNAL",
      "-include", "stdlib.h",
      "-include", "stdint.h",
    ],
    deps = ["//libressl"],
    visibility = ["//visibility:public"],
)

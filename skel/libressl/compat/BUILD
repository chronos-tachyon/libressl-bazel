# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

cc_library(
    name = "compat",
    hdrs = glob(["**/*.h"]),
    srcs = [
      "arc4random.c",
      "explicit_bzero.c",
      "issetugid_linux.c",
      "reallocarray.c",
      "strlcat.c",
      "strlcpy.c",
      "strtonum.c",
      "timingsafe_memcmp.c",
    ],
    deps = [
      ":getentropy",
    ],
    visibility = [
      "//libressl/crypto:__pkg__",
      "//libressl/ssl:__pkg__",
    ],
)

cc_library(
    name = "getentropy",
    srcs = [
      "getentropy_linux.c",
      "//openssl:headers",
    ],
    copts = ["-include", "stddef.h", "-include", "linux/sysctl.h"],
)

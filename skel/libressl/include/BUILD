# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

filegroup(
    name = "include",
    srcs = [
      ":compat",
      ":libcrypto",
      ":libssl",
      ":libtls",
    ],
    visibility = ["//libressl:__pkg__"],
)

filegroup(
    name = "compat",
    srcs = glob([
      "arpa/inet.h",
      "machine/endian.h",
      "netinet/in.h",
      "netinet/tcp.h",
      "sys/ioctl.h",
      "sys/mman.h",
      "sys/select.h",
      "sys/socket.h",
      "sys/times.h",
      "sys/types.h",
      "sys/uio.h",
      "arc4random*.h",
      "chacha_private.h",
      "err.h",
      "netdb.h",
      "poll.h",
      "stdio.h",
      "stdlib.h",
      "string.h",
      "syslog.h",
      "unistd.h",
      "win32netcompat.h",
    ]),
    visibility = ["//libressl:__subpackages__"],
)

filegroup(
    name = "libcrypto",
    srcs = {{libcrypto_headers}},
    visibility = ["//libressl/crypto:__pkg__"],
)

filegroup(
    name = "libssl",
    srcs = {{libssl_headers}},
    visibility = ["//libressl/ssl:__pkg__"],
)

filegroup(
    name = "libtls",
    srcs = {{libtls_headers}},
    visibility = ["//libressl/tls:__pkg__"],
)

cc_library(
    name = "pqueue",
    hdrs = ["pqueue.h"],
    visibility = ["//libressl/ssl:__pkg__"],
)

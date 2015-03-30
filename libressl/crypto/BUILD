# http://bazel.io/
# vim: set ft=python sts=2 sw=2 et:

UNKNOWN_SRCS = [
    "aes/aes_cbc.c",
    "aes/aes_core.c",
    "bf/bf_enc.c",
    "bn/bn_asm.c",
    "camellia/camellia.c",
    "camellia/cmll_cbc.c",
    "camellia/cmll_misc.c",
    "des/des_enc.c",
    "des/fcrypt_b.c",
    "rc4/rc4_enc.c",
    "rc4/rc4_skey.c",
    "whrlpool/wp_block.c",
]
UNKNOWN_OPTS = [
    "-DOPENSSL_NO_ASM",
]

I386_SRCS = [
    "bf/bf_cbc.c",
    "des/fcrypt_b.c",
    "whrlpool/wp_block.c",
]
I386_OPTS = [
    "-DAES_ASM",
    "-DVPAES_ASM",
    "-DOPENSSL_IA32_SSE2",
    "-DOPENSSL_BN_ASM_PART_WORDS",
    "-DOPENSSL_BN_ASM_MONT",
    "-DOPENSSL_BN_ASM_GF2m",
    "-DMD5_ASM",
    "-DGHASH_ASM",
    "-DRMD160_ASM",
    "-DSHA1_ASM",
    "-DSHA256_ASM",
    "-DSHA512_ASM",
    "-DWHIRLPOOL_ASM",
    "-DOPENSSL_CPUID_OBJ",
]

AMD64_SRCS = [
    "bf/bf_enc.c",
    "bn/asm/x86_64-gcc.c",
    "camellia/cmll_misc.c",
    "des/des_enc.c",
    "des/fcrypt_b.c",
]
AMD64_OPTS = [
    "-DAES_ASM",
    "-DBSAES_ASM",
    "-DVPAES_ASM",
    "-DOPENSSL_IA32_SSE2",
    "-DRSA_ASM",
    "-DOPENSSL_BN_ASM_MONT",
    "-DOPENSSL_BN_ASM_MONT5",
    "-DOPENSSL_BN_ASM_GF2m",
    "-DMD5_ASM",
    "-DGHASH_ASM",
    "-DRC4_MD5_ASM",
    "-DSHA1_ASM",
    "-DSHA256_ASM",
    "-DSHA512_ASM",
    "-DWHIRLPOOL_ASM",
    "-DOPENSSL_CPUID_OBJ",
]

PICKY_SRCS = UNKNOWN_SRCS + I386_SRCS + AMD64_SRCS
GENERIC_SRCS = glob(["**/*.c", "**/*.h"], exclude=PICKY_SRCS)

GENERIC_COPTS = [
    "-DNULL=((void*)0)",
    "-Ilibressl/compat",
    "-Ilibressl/crypto",
    "-Ilibressl/crypto/asn1",
    "-Ilibressl/crypto/evp",
    "-Ilibressl/crypto/modes",
]

cc_library(
    name = "crypto",
    hdrs = ["//openssl:libcrypto_headers"],
    srcs = select({
      "//libressl:asm-i386-elf": GENERIC_SRCS + I386_SRCS + glob(["**/*-elf-x86.S"]),
      "//libressl:asm-i386-macosx": GENERIC_SRCS + I386_SRCS + glob(["**/*-macosx-x86.S"]),
      "//libressl:asm-amd64-elf": GENERIC_SRCS + AMD64_SRCS + glob(["**/*-elf-x86_64.S"]),
      "//libressl:asm-amd64-macosx": GENERIC_SRCS + AMD64_SRCS + glob(["**/*-macosx-x86_64.S"]),
      "//conditions:default": GENERIC_SRCS + UNKNOWN_SRCS,
    }),
    deps = ["//libressl/compat"],
    copts = select({
      "//libressl:asm-i386-elf": GENERIC_COPTS + I386_OPTS,
      "//libressl:asm-i386-macosx": GENERIC_COPTS + I386_OPTS,
      "//libressl:asm-amd64-elf": GENERIC_COPTS + AMD64_OPTS,
      "//libressl:asm-amd64-macosx": GENERIC_COPTS + AMD64_OPTS,
      "//conditions:default": GENERIC_COPTS + UNKNOWN_OPTS,
    }),
    visibility = ["//libressl:__pkg__"],
)

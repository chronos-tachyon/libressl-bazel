LibreSSL Bazel is a LibreSSL fork that has been adapted to use [Bazel][1].

LibreSSL is a fork of OpenSSL developed by [the OpenBSD project][2].  LibreSSL
is developed on OpenBSD; the related project [LibreSSL Portable][3] then adds
portability shims for other operating systems.  This fork of LibreSSL Portable
adds additional shims for using LibreSSL within [Bazel][1] projects.

To use this package:

  1.  Install Bazel on your system.

      $ cd ~/src
      $ git clone https://github.com/google/bazel.git
      $ cd bazel
      $ ./compile.sh
      $ output/bazel build //src:bazel
      # Assuming ~/bin exists and is in $PATH...
      $ cp -pf bazel-bin/src/bazel ~/bin/bazel

  2.  Create or download a project that uses Bazel and needs LibreSSL.

      $ cd ~/src
      $ git clone https://example.org/my-project
      $ cd my-project
      $ ln -s ../bazel/third_party
      $ ln -s ../bazel/tools
      $ bazel build //foo  # fails
      $ less foo/BUILD  # depends on //openssl or //libressl

  3.  Fetch LibreSSL to your system and symlink it in.

      $ cd ~/src/my-project
      $ git clone https://github.com/chronos-tachyon/libressl-bazel ../libressl-bazel
      $ ln -s ../libressl-bazel/libressl
      $ ln -s ../libressl-bazel/openssl
      $ bazel build //foo  # now works

[1]: http://bazel.io/
[2]: http://www.openbsd.org/
[3]: https://github.com/libressl-portable/portable

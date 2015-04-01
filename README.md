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
        $ cp -pf bazel-bin/src/bazel ~/bin/bazel

2.  Create or download a project that uses Bazel and needs LibreSSL.
        $ cd ..
        $ git clone https://example.org/my-project
        $ cd my-project
        $ ln -s ../bazel/third_party
        $ ln -s ../bazel/tools
        # Write rule "foo" in file "foo/BUILD"
        $ bazel build //foo  # fails, depends on //libressl

3.  Fetch LibreSSL and symlink it in, e.g. using git submodules.

        $ git stash
        $ git submodule add https://github.com/chronos-tachyon/libressl-bazel .modules/libressl
        $ ln -s .modules/libressl/libressl
        $ git add libressl
        $ git commit -m "Add dependency on LibreSSL"
        $ git stash pop
        $ bazel build //foo  # now works

[1]: http://bazel.io/
[2]: http://www.openbsd.org/
[3]: https://github.com/libressl-portable/portable

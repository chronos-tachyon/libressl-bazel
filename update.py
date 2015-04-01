#!/usr/bin/env python
# vim:set ft=python ts=8 sts=2 sw=2 et:
# This file is in the Public Domain.
# Originally written by Donald King <https://github.com/chronos-tachyon>.
#
# Verified as working in Python 2.7.6 and 3.4.0 by Donald King on 2015-03-28.
"""Regenerates the LibreSSL Bazel release from the LibreSSL OpenBSD source."""

from __future__ import print_function
import argparse
import errno
import os
import re
import shutil
import subprocess
import sys
import tempfile


UPSTREAM_URL = 'https://github.com/libressl-portable/openbsd.git'

COMPAT_HEADERS = (
    'libcrypto/crypto/arc4random_freebsd.h',
    'libcrypto/crypto/arc4random_hpux.h',
    'libcrypto/crypto/arc4random_linux.h',
    'libcrypto/crypto/arc4random_netbsd.h',
    'libcrypto/crypto/arc4random_osx.h',
    'libcrypto/crypto/arc4random_solaris.h',
    'libcrypto/crypto/arc4random_win.h',
    'libc/crypt/chacha_private.h',
)
COMPAT_SOURCES = (
    'libc/crypt/arc4random.c',
    'libc/stdlib/reallocarray.c',
    'libc/stdlib/strtonum.c',
    'libc/string/explicit_bzero.c',
    'libc/string/strlcat.c',
    'libc/string/strlcpy.c',
    'libc/string/strndup.c',
    'libc/string/strnlen.c',
    'libc/string/strsep.c',
    'libc/string/timingsafe_bcmp.c',
    'libc/string/timingsafe_memcmp.c',
)

LIBCRYPTO_HEADERS = (
    'GENERATED/obj_mac.h',
    'libcrypto/crypto/arch/amd64/opensslconf.h',
    'libssl/src/crypto/aes/aes.h',
    'libssl/src/crypto/asn1/asn1t.h',
    'libssl/src/crypto/asn1/asn1.h',
    'libssl/src/crypto/asn1/asn1_mac.h',
    'libssl/src/crypto/bf/blowfish.h',
    'libssl/src/crypto/bio/bio.h',
    'libssl/src/crypto/bn/bn.h',
    'libssl/src/crypto/buffer/buffer.h',
    'libssl/src/crypto/camellia/camellia.h',
    'libssl/src/crypto/cast/cast.h',
    'libssl/src/crypto/chacha/chacha.h',
    'libssl/src/crypto/cmac/cmac.h',
    'libssl/src/crypto/cms/cms.h',
    'libssl/src/crypto/comp/comp.h',
    'libssl/src/crypto/conf/conf.h',
    'libssl/src/crypto/conf/conf_api.h',
    'libssl/src/crypto/crypto.h',
    'libssl/src/crypto/des/des.h',
    'libssl/src/crypto/dh/dh.h',
    'libssl/src/crypto/dsa/dsa.h',
    'libssl/src/crypto/dso/dso.h',
    'libssl/src/crypto/ecdh/ecdh.h',
    'libssl/src/crypto/ecdsa/ecdsa.h',
    'libssl/src/crypto/ec/ec.h',
    'libssl/src/crypto/engine/engine.h',
    'libssl/src/crypto/err/err.h',
    'libssl/src/crypto/evp/evp.h',
    'libssl/src/crypto/gost/gost.h',
    'libssl/src/crypto/hmac/hmac.h',
    'libssl/src/crypto/idea/idea.h',
    'libssl/src/crypto/krb5/krb5_asn.h',
    'libssl/src/crypto/lhash/lhash.h',
    'libssl/src/crypto/md4/md4.h',
    'libssl/src/crypto/md5/md5.h',
    'libssl/src/crypto/mdc2/mdc2.h',
    'libssl/src/crypto/modes/modes.h',
    'libssl/src/crypto/objects/objects.h',
    'libssl/src/crypto/ocsp/ocsp.h',
    'libssl/src/crypto/opensslfeatures.h',
    'libssl/src/crypto/opensslv.h',
    'libssl/src/crypto/ossl_typ.h',
    'libssl/src/crypto/pem/pem2.h',
    'libssl/src/crypto/pem/pem.h',
    'libssl/src/crypto/pkcs7/pkcs7.h',
    'libssl/src/crypto/pkcs12/pkcs12.h',
    'libssl/src/crypto/poly1305/poly1305.h',
    'libssl/src/crypto/rand/rand.h',
    'libssl/src/crypto/rc2/rc2.h',
    'libssl/src/crypto/rc4/rc4.h',
    'libssl/src/crypto/ripemd/ripemd.h',
    'libssl/src/crypto/rsa/rsa.h',
    'libssl/src/crypto/sha/sha.h',
    'libssl/src/crypto/stack/safestack.h',
    'libssl/src/crypto/stack/stack.h',
    'libssl/src/crypto/ts/ts.h',
    'libssl/src/crypto/txt_db/txt_db.h',
    'libssl/src/crypto/ui/ui.h',
    'libssl/src/crypto/ui/ui_compat.h',
    'libssl/src/crypto/whrlpool/whrlpool.h',
    'libssl/src/crypto/x509v3/x509v3.h',
    'libssl/src/crypto/x509/x509.h',
    'libssl/src/crypto/x509/x509_vfy.h',
    'libssl/src/e_os2.h',
)
LIBSSL_HEADERS = (
    'libssl/src/ssl/dtls1.h',
    'libssl/src/ssl/srtp.h',
    'libssl/src/ssl/ssl2.h',
    'libssl/src/ssl/ssl3.h',
    'libssl/src/ssl/ssl23.h',
    'libssl/src/ssl/ssl.h',
    'libssl/src/ssl/tls1.h',
)
LIBTLS_HEADERS = (
    'libssl/src/ssl/pqueue.h',
    'libtls/tls.h',
)
NOTLS_HEADERS = LIBCRYPTO_HEADERS + LIBSSL_HEADERS
PUBLISHED = LIBTLS_HEADERS + NOTLS_HEADERS

DISCARD = (
    # Conflicting headers (we only keep arch/amd64)
    'libcrypto/crypto/arch/alpha/opensslconf.h',
    'libcrypto/crypto/arch/arm/opensslconf.h',
    'libcrypto/crypto/arch/hppa64/opensslconf.h',
    'libcrypto/crypto/arch/hppa/opensslconf.h',
    'libcrypto/crypto/arch/i386/opensslconf.h',
    'libcrypto/crypto/arch/m88k/opensslconf.h',
    'libcrypto/crypto/arch/mips64/opensslconf.h',
    'libcrypto/crypto/arch/powerpc/opensslconf.h',
    'libcrypto/crypto/arch/sh/opensslconf.h',
    'libcrypto/crypto/arch/sparc64/opensslconf.h',
    'libcrypto/crypto/arch/sparc/opensslconf.h',
    'libcrypto/crypto/arch/vax/opensslconf.h',

    # Stuff not included in LibreSSL Portable
    'libssl/src/crypto/aes/aes_x86core.c',
    'libssl/src/crypto/armcap.c',
    'libssl/src/crypto/arm_arch.h',
    'libssl/src/crypto/bio/bf_lbuf.c',
    'libssl/src/crypto/cms/cms_asn1.c',
    'libssl/src/crypto/cms/cms_att.c',
    'libssl/src/crypto/cms/cms_cd.c',
    'libssl/src/crypto/cms/cms_dd.c',
    'libssl/src/crypto/cms/cms_enc.c',
    'libssl/src/crypto/cms/cms_env.c',
    'libssl/src/crypto/cms/cms_err.c',
    'libssl/src/crypto/cms/cms_ess.c',
    'libssl/src/crypto/cms/cms_io.c',
    'libssl/src/crypto/cms/cms_lcl.h',
    'libssl/src/crypto/cms/cms_lib.c',
    'libssl/src/crypto/cms/cms_pwri.c',
    'libssl/src/crypto/cms/cms_sd.c',
    'libssl/src/crypto/cms/cms_smime.c',
    'libssl/src/crypto/ec/ecp_nistp224.c',
    'libssl/src/crypto/ec/ecp_nistp256.c',
    'libssl/src/crypto/ec/ecp_nistp521.c',
    'libssl/src/crypto/ec/ecp_nistputil.c',
    'libssl/src/crypto/engine/eng_aesni.c',
    'libssl/src/crypto/ppccap.c',
    'libssl/src/crypto/s390xcap.c',
    'libssl/src/crypto/sparcv9cap.c',
    'libssl/src/crypto/uid.c',
    'libssl/src/test/asn1test.c',
    'libssl/src/test/methtest.c',
    'libssl/src/test/r160test.c',

    # Source files that are #include'd by other source files
    'libssl/src/crypto/poly1305/poly1305-donna.c',
    'libssl/src/crypto/chacha/chacha-merged.c',
    'libssl/src/crypto/des/ncbc_enc.c',
)


def Open(path, mode):
  if str is bytes:
    return open(path, mode)
  else:
    return open(path, mode, encoding='latin1')


def Read(path):
  """Slurp in the contents of a file."""
  with Open(path, 'r') as fh:
    return fh.read()


def Run(argv, **kwargs):
  if Run.loud:
    print(*argv)

  try:
    subprocess.check_call(argv, **kwargs)
    return
  except subprocess.CalledProcessError as e:
    err = 'returned exit code ' + str(e.returncode)
  except OSError as e:
    err = str(e)

  msg = 'ERROR: ' + repr(argv)
  cwd = kwargs.get('cwd', None)
  if cwd:
    cwd = os.path.relpath(cwd)
    msg += ' (cwd: ' + repr(cwd) + ')'
  msg += ': ' + err
  print(msg, file=sys.stderr)
  sys.exit(1)
Run.loud = False


def Copy(srcpath, dstpath, transforms=(), preserve=False):
  """Copies a single file, with optional transformations of the data.

  The transforms kwarg takes a sequence of content transformations, each of
  which is a callable that receives two string arguments (relative destination
  path, previously proposed contents) and returns a string (newly proposed
  contents).  Transformations are applied serially in a chain, with the first
  transformation receiving the source file's original contents and the last
  transformation returning the final contents for the destination file.

  Args:
    srcpath: path to the source file.
    dstpath: path to the destination file.
    transforms: a sequence of content transformation functions.
  """
  try:
    os.makedirs(os.path.dirname(dstpath))
  except OSError as e:
    if e.errno != errno.EEXIST: raise

  cmd = ['cp', '--no-target-directory', '--preserve=all']
  if preserve or Copy.keep:
    cmd.append('--no-clobber')
  else:
    cmd.append('--force')

  if transforms:
    original = Read(srcpath)
    data = original
    for transform in transforms:
      data = transform(srcpath, data)
    if data != original:
      with Open(dstpath, 'w') as fh:
        fh.write(data)
      cmd.pop()
      cmd.append('--attributes-only')

  cmd.extend(('--', srcpath, dstpath))
  Run(cmd)
Copy.keep = True


# For os.walk
def Raise(e):
  raise e


# For list.sort(key=) / sorted(key=)
def ByVersion(key):
  def Fn(piece):
    try:
      return (0, int(piece))
    except ValueError:
      return (1, piece)
  return [Fn(x) for x in re.split(r'(\d+|\W+)', key)]


class Tree(object):
  __slots__ = ('root', 'items')

  def __init__(self, root, items=()):
    self.root = os.path.abspath(root)
    self.items = items

  def __iter__(self):
    return iter(self.items)

  def Scan(self):
    items = []
    for path, subdirs, subfiles in os.walk(self.root, onerror=Raise):
      if '.git' in subdirs: subdirs.remove('.git')
      if '.svn' in subdirs: subdirs.remove('.svn')
      subdirs.sort(key=ByVersion)
      subfiles.sort(key=ByVersion)
      for filename in subfiles:
        items.append(os.path.join(path, filename))
    self.items = items
    return self

  def SubTree(self, path):
    path = os.path.normpath(os.path.join(self.root, path))
    prefix = path + os.sep
    return Tree(path, items=[i for i in self.items if i.startswith(prefix)])

  def Find(self, predicate):
    for srcpath in self.items:
      if predicate(srcpath):
        yield srcpath

  def CopyTo(self, dstdir,
             predicate=lambda _: True,
             rename=lambda x: x,
             flatten=False,
             transforms=()):
    """Copies a tree of files.

    The predicate kwarg takes a pathname predicate, which is a callable that
    takes an absolute pathname in the source tree and returns a bool -- True if
    the file should be copied, False if it should not.

    The rename kwarg takes a path transformation, which is a callable that takes
    a relative path in the source tree and returns a relative path in the
    destination tree.  The default is the identity function.

    For more on the transforms kwarg, see the Copy function.

    Args:
      srcdir: path to the root of the source directory tree.
      dstdir: path to the root of the destination directory tree.
      predicate: a path predicate function.
      rename: a path transformation function.
      flatten: if True, flattens the destination tree (after rename).
      transforms: a sequence of content transformation functions.
    """
    for srcpath in self.Find(predicate):
      dstpath = rename(os.path.relpath(srcpath, self.root))
      if flatten:
        dstpath = os.path.basename(dstpath)
      dstpath = os.path.join(dstdir, dstpath)
      Copy(srcpath, dstpath, transforms=transforms)


def Not(child):
  def Predicate(path):
    return not child(path)
  return Predicate


def And(*children):
  def Predicate(path):
    return all(f(path) for f in children)
  return Predicate


def Or(*children):
  def Predicate(path):
    return any(f(path) for f in children)
  return Predicate


def IsPattern(pattern):
  regexp = re.compile(pattern)
  def Predicate(path):
    return regexp.search(path)
  Predicate.regexp = regexp
  return Predicate


def IsIn(collection):
  pattern = '|'.join(re.escape(x) for x in sorted(collection))
  pattern = '(?:^|/)(?:' + pattern + ')$'
  return IsPattern(pattern)


def Replace(pattern, replacement,
            predicate=lambda _: True):
  """A factory for regex-based Copy transformations."""
  regex = re.compile(pattern)
  def TransformFunction(path, data):
    if predicate(path):
      return regex.sub(replacement, data)
    else:
      return data
  return TransformFunction


def InlineCInclude(path, data):
  if path.endswith('.c') and InlineCInclude.regexp.search(data):
    dir = os.path.dirname(path)
    subst = lambda m: Read(os.path.join(dir, m.group(1)))
    data = InlineCInclude.regexp.sub(subst, data)
  return data
InlineCInclude.regexp = re.compile(
    r'^\s*#\s*include\s+"([\w-]+\.c)"(?:\s+|/\*.*?\*/|//.*)*?$',
    re.M | re.S)


def LoadManLinks(man_links, path):
  """Reads in a specially-formatted Makefile that lists manpage symlinks."""
  seen = {}
  with Open(path, 'r') as fh:
    for line in fh:
      m = re.match(r'^\t(\w+\.[1-8]\w*)\s+(\w+\.[1-8]\w*)\s*\\\s*$', line)
      if m:
        target, linkname = m.groups()
        if linkname in seen:
          if seen[linkname] == target:
            msg = 'duplicate symlinks for {link!r} -> {old!r}'
          else:
            msg = 'conflicting symlinks {link!r} -> {old!r} vs {new!r}'
          print('WARNING: ' +
                msg.format(old=seen[linkname], new=target, link=linkname),
                file=sys.stderr)
          continue
        seen[linkname] = target
        man_links.append((target, linkname))


def ParseArgs(argv):
  class MyHelpFormatter(argparse.RawDescriptionHelpFormatter,
                        argparse.ArgumentDefaultsHelpFormatter):
    pass

  root = os.path.dirname(argv[0])
  parser = argparse.ArgumentParser(prog=argv[0],
                                   description=__doc__,
                                   formatter_class=MyHelpFormatter)
  parser.add_argument('-s', '--source_dir', metavar='DIR',
                      help='The path to the libressl-bazel repository',
                      default=root)
  parser.add_argument('-d', '--destination_dir', metavar='DIR',
                      help='The output path',
                      default=root)
  parser.add_argument('-u', '--upstream_dir', metavar='DIR',
                      help='The path to the upstream OpenBSD repository',
                      default=os.path.join(root, 'openbsd'))
  parser.add_argument('-U', '--upstream_url', metavar='URL',
                      help='The Git URL to the upstream OpenBSD repository',
                      default=UPSTREAM_URL)
  parser.add_argument('-P', '--skip_pull', action='store_true',
                      help=('Assume that the local clone of the upstream '
                            'OpenBSD repository is already up-to-date'))
  parser.add_argument('-C', '--skip_clean', action='store_true',
                      help='Do not clear destination directory before copying')
  parser.add_argument('-k', '--keep', action='store_true',
                      help='Preserve existing files')
  parser.add_argument('-v', '--verbose', action='store_true',
                      help='Show the commandlines being run')
  args = parser.parse_args(argv[1:])
  args.source_dir = os.path.abspath(args.source_dir)
  args.destination_dir = os.path.abspath(args.destination_dir)
  args.upstream_dir = os.path.abspath(args.upstream_dir)
  return args


def Pull(args, branch_name):
  if not args.skip_pull:
    print('Pulling latest LibreSSL OpenBSD sources from upstream...')
    if not os.path.isdir(args.upstream_dir):
      Run(['git', 'clone', args.upstream_url, args.upstream_dir])
    Run(['git', 'checkout', branch_name], cwd=args.upstream_dir)
    Run(['git', 'pull', '--rebase'], cwd=args.upstream_dir)


def Clean(args):
  if not args.skip_clean:
    print('Cleaning destination directory...')
    for subdir in ('libressl', 'openssl', 'man'):
      try:
        shutil.rmtree(os.path.join(args.destination_dir, subdir))
      except OSError as e:
        if e.errno != errno.ENOENT: raise


def GenerateAsm(scriptroot, dstroot, scriptdir, scriptname, cpu, abi):
  if cpu not in ('x86', '586', 'x86_64'):
    raise ValueError('Unknown CPU {!r}'.format(cpu))
  if abi not in ('elf', 'macosx'):
    raise ValueError('Unknown ABI {!r}'.format(abi))

  kvin = {'dir': scriptdir, 'name': scriptname, 'cpu': cpu, 'abi': abi}
  kvout = kvin.copy()
  if cpu == '586':
    kvout['cpu'] = 'x86'
  if cpu == 'x86_64' and scriptname == 'sha256':
    kvin['name'] = 'sha512'

  if scriptdir:
    patterns = ('{dir}/asm/{name}-{abi}-{cpu}.pl',
                '{dir}/asm/{name}-{cpu}.pl',
                '{dir}/asm/{cpu}-{name}.pl')
    outpattern = '{dir}/{name}-{abi}-{cpu}.S'
  else:
    patterns = ('{name}-{cpu}.pl',
                '{cpu}-{name}.pl',
                '{cpu}{name}.pl')
    outpattern = '{name}-{abi}-{cpu}.S'
  for pattern in patterns:
    script = os.path.join(scriptroot, pattern.format(**kvin))
    if os.path.exists(script):
      out = os.path.join(dstroot, outpattern.format(**kvout))
      prefix = os.path.basename(out)
      with tempfile.NamedTemporaryFile(prefix=prefix) as tmp:
        cmd = ['perl', script, abi]
        if cpu == 'x86' or cpu == '586':
          cmd.append('386')
        if cpu == 'x86_64':
          cmd.append(tmp.name)
        Run(cmd, stdout=tmp)
        appendix = ''
        if cpu == 'x86_64' and abi == 'elf':
          appendix = ('\n'
                      '#if defined(HAVE_GNU_STACK)\n'
                      '.section .note.GNU-stack,"",%progbits\n'
                      '#endif\n')
        Copy(tmp.name, out,
             transforms=[lambda _, data: data + appendix])
      return
  if cpu == 'x86':
    GenerateAsm(scriptroot, dstroot, scriptdir, scriptname, '586', abi)


def ConvertPod(podpath, manpath, release='LibreSSL'):
  name, section = os.path.splitext(os.path.basename(manpath))
  section = section[1:]
  with tempfile.NamedTemporaryFile() as tmp:
    with Open(podpath, 'r') as pod:
      Run([
        'pod2man',
        '--official',
        '--release=' + release,
        '--center=LibreSSL',
        '--section=' + section,
        '--name=' + name,
      ], stdin=pod, stdout=tmp)
    Copy(tmp.name, manpath, preserve=True)


def main(argv):
  os.umask(022)
  args = ParseArgs(argv)
  Copy.keep = args.keep
  Run.loud = args.verbose

  SRC = lambda *x: os.path.join(args.source_dir, *x)
  DST = lambda *x: os.path.join(args.destination_dir, *x)
  BSD = lambda *x: os.path.join(args.upstream_dir, *x)

  openbsd_branch = Read(SRC('OPENBSD_BRANCH')).rstrip('\r\n')
  libressl_version = Read(SRC('VERSION')).rstrip('\r\n')
  print('Version information: branch {!r}, version {!r}'
        .format(openbsd_branch, libressl_version))

  Pull(args, openbsd_branch)
  Clean(args)

  def Headers(container, subdir=None):
    if subdir:
      fn = lambda x: os.path.join(subdir, os.path.basename(x))
    else:
      fn = lambda x: os.path.basename(x)
    return sorted(map(fn, container), key=ByVersion)

  subst_vars = {'openbsd_branch': openbsd_branch,
                'libressl_version': libressl_version}
  subst_vars['libcrypto_headers'] = Headers(LIBCRYPTO_HEADERS, subdir='openssl')
  subst_vars['libssl_headers'] = Headers(LIBSSL_HEADERS, subdir='openssl')
  subst_vars['libtls_headers'] = Headers(LIBTLS_HEADERS)
  subst_match = '|'.join(re.escape(x) for x in sorted(subst_vars))
  subst_match = r'\{\{(' + subst_match + r')\}\}'

  IsSource = IsPattern(r'\.[chSs]$')
  standard_transforms = [
    Replace(subst_match, lambda m: repr(subst_vars[m.group(1)])),
    Replace(r'"LibreSSL [^"]*"',
            '"LibreSSL {}"'.format(libressl_version),
            predicate=lambda x: x.endswith('/opensslv.h')),
    InlineCInclude,
  ]

  skel = Tree(SRC('skel')).Scan()
  openbsd = Tree(BSD()).Scan()

  print('Copying skeleton...')
  skel.CopyTo(DST(), transforms=standard_transforms)
  Copy(BSD('src/lib/libssl/src/LICENSE'), DST('COPYING'))
  if not os.path.samefile(args.source_dir, args.destination_dir):
    Copy(SRC('AUTHORS'), DST('AUTHORS'))
    Copy(SRC('BUILD'), DST('BUILD'))
    Copy(SRC('ChangeLog'), DST('ChangeLog'))
    Copy(SRC('NEWS'), DST('NEWS'))
    Copy(SRC('README.md'), DST('README.md'))
    Copy(SRC('README.original'), DST('README.original'))
    Copy(SRC('README.windows'), DST('README.windows'))
    Copy(SRC('WORKSPACE'), DST('WORKSPACE'))

  print('Copying headers...')
  openbsd_srclib = openbsd.SubTree('src/lib')
  openbsd_srclib.CopyTo(
      DST('libressl/include'),
      predicate=IsIn(LIBTLS_HEADERS),
      flatten=True,
      transforms=standard_transforms)
  openbsd_srclib.CopyTo(
      DST('libressl/include/openssl'),
      predicate=IsIn(NOTLS_HEADERS),
      flatten=True,
      transforms=standard_transforms)
  openbsd_srclib.CopyTo(
      DST('libressl/include'),
      predicate=IsIn(COMPAT_HEADERS),
      flatten=True,
      transforms=standard_transforms)

  print('Copying compatibility sources...')
  openbsd_srclib.CopyTo(
      DST('libressl/crypto/compat'),
      predicate=IsIn(COMPAT_SOURCES),
      flatten=True,
      transforms=standard_transforms)

  print('Copying libssl sources...')
  openbsd.SubTree('src/lib/libssl/src').CopyTo(
      DST('libressl'),
      predicate=And(IsSource, Not(IsIn(PUBLISHED)), Not(IsIn(DISCARD))),
      transforms=standard_transforms)

  print('Copying libtls sources...')
  openbsd.SubTree('src/lib/libtls').CopyTo(
      DST('libressl/tls'),
      predicate=And(IsSource, Not(IsIn(PUBLISHED)), Not(IsIn(DISCARD))),
      transforms=standard_transforms)

  print('Copying openssl(1) application sources...')
  openbsd.SubTree('src/usr.bin/openssl').CopyTo(
      DST('libressl/apps'),
      predicate=And(IsSource, Not(IsIn(PUBLISHED)), Not(IsIn(DISCARD))),
      transforms=standard_transforms)
  Copy(BSD('src/lib/libcrypto/openssl.cnf'), DST('libressl/apps/openssl.cnf'))

  print('Generating obj_mac.h and obj_dat.h...')
  with tempfile.NamedTemporaryFile() as tmp1:
    Run([
      'perl',
      'objects.pl',
      'objects.txt',
      'obj_mac.num',
      tmp1.name,
    ], cwd=BSD('src/lib/libssl/src/crypto/objects'))
    with tempfile.NamedTemporaryFile() as tmp2:
      Run([
        'perl',
        'obj_dat.pl',
        tmp1.name,
        tmp2.name,
      ], cwd=BSD('src/lib/libssl/src/crypto/objects'))
      Copy(tmp1.name, DST('libressl/include/openssl/obj_mac.h'),
           transforms=standard_transforms)
      Copy(tmp2.name, DST('libressl/crypto/objects/obj_dat.h'),
           transforms=standard_transforms)

  asm_src = BSD('src/lib/libssl/src/crypto')
  asm_dst = DST('libressl/crypto')
  for cpu, abi in (('x86', 'elf'),
                   ('x86', 'macosx'),
                   ('x86_64', 'elf'),
                   ('x86_64', 'macosx')):
      print('Generating ASM sources for cpu={cpu!r}, abi={abi!r}...'
            .format(cpu=cpu, abi=abi))
      GenerateAsm(asm_src, asm_dst, 'aes', 'aes', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'aes', 'vpaes', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'aes', 'bsaes', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'aes', 'aesni', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'aes', 'aesni-sha1', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'bn', 'modexp512', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'bn', 'mont', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'bn', 'mont5', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'bn', 'gf2m', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'camellia', 'cmll', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'md5', 'md5', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'modes', 'ghash', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'rc4', 'rc4', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'rc4', 'rc4-md5', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'sha', 'sha1', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'sha', 'sha256', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'sha', 'sha512', cpu, abi)
      GenerateAsm(asm_src, asm_dst, 'whrlpool', 'wp', cpu, abi)
      GenerateAsm(asm_src, asm_dst, '', 'cpuid', cpu, abi)

  print('Copying test sources...')

  Copy(BSD('src/regress/lib/libc/arc4random-fork/arc4random-fork.c'),
       DST('libressl/tests/arc4randomforktest.c'))
  Copy(BSD('src/regress/lib/libc/explicit_bzero/explicit_bzero.c'),
       DST('libressl/tests/explicit_bzero.c'))
  Copy(BSD('src/regress/lib/libc/timingsafe/timingsafe.c'),
       DST('libressl/tests/timingsafe.c'))
  Copy(BSD('src/lib/libc/string/memmem.c'),
       DST('libressl/tests/memmem.c'))

  openbsd.SubTree('src/regress/lib/libcrypto').CopyTo(
      DST('libressl/tests'),
      predicate=IsSource,
      flatten=True,
      transforms=standard_transforms)
  Copy(BSD('src/regress/lib/libcrypto/aead/aeadtests.txt'),
       DST('libressl/tests/aeadtests.txt'))
  Copy(BSD('src/regress/lib/libcrypto/evp/evptests.txt'),
       DST('libressl/tests/evptests.txt'))
  Copy(BSD('src/regress/lib/libcrypto/pqueue/expected.txt'),
       DST('libressl/tests/pq_expected.txt'))

  openbsd.SubTree('src/regress/lib/libssl').CopyTo(
      DST('libressl/tests'),
      predicate=IsSource,
      flatten=True,
      transforms=standard_transforms)
  Copy(BSD('src/regress/lib/libssl/certs/ca.pem'),
       DST('libressl/tests/ca.pem'))
  Copy(BSD('src/regress/lib/libssl/certs/server.pem'),
       DST('libressl/tests/server.pem'))

  print('Copying manual pages...')

  IsManPage = And(IsPattern(r'\.[1-8]$'), Not(IsPattern(r'VMSca-response')))

  def RenameManPage(path):
    path = os.path.basename(path)
    section = os.path.splitext(path)[1][1:]
    suffix = 'ssl' if len(section) == 1 else ''
    return os.path.join('man' + section[0], path + suffix)

  openbsd.SubTree('src/usr.bin/openssl').CopyTo(
      DST('man'),
      predicate=IsManPage,
      rename=RenameManPage)
  openbsd.SubTree('src/lib/libcrypto').CopyTo(
      DST('man'),
      predicate=IsManPage,
      rename=RenameManPage)
  openbsd.SubTree('src/lib/libssl').CopyTo(
      DST('man'),
      predicate=IsManPage,
      rename=RenameManPage)
  openbsd.SubTree('src/lib/libtls').CopyTo(
      DST('man'),
      predicate=IsManPage,
      rename=RenameManPage)

  print('Converting POD documentation to manual pages...')
  openbsd_appdoc = openbsd.SubTree('src/lib/libssl/src/doc/apps')
  for podpath in openbsd_appdoc.Find(IsPattern(r'\.pod$')):
    base = os.path.basename(podpath)[:-4]
    manpath = DST('man/man1/' + base + '.1ssl')
    ConvertPod(podpath, manpath, release='LibreSSL ' + libressl_version)
  openbsd_cryptodoc = openbsd.SubTree('src/lib/libssl/src/doc/crypto')
  for podpath in openbsd_cryptodoc.Find(IsPattern(r'\.pod$')):
    base = os.path.basename(podpath)[:-4]
    manpath = DST('man/man3/' + base + '.3ssl')
    ConvertPod(podpath, manpath, release='LibreSSL ' + libressl_version)

  print('Generating symlinks to aliased manual pages...')
  man_links = []
  LoadManLinks(man_links, BSD('src/lib/libcrypto/man/Makefile'))
  for target, linkname in man_links:
    section = target[-1]
    target += 'ssl'
    linkname += 'ssl'
    linkpath = os.path.relpath(DST('man/man' + section, linkname))
    if os.path.islink(linkpath):
      if os.readlink(linkpath) == target:
        continue
      os.unlink(linkpath)
    os.symlink(target, linkpath)

  print('Done.')


if __name__ == '__main__':
  sys.exit(main(sys.argv) or 0)

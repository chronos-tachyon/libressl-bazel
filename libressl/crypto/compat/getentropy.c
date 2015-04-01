/*
 * getentropy implementation
 * Public domain
 *
 * http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man2/getentropy.2
 */

#if defined(__OpenBSD__)
#ifndef HAVE_GETENTROPY
#define HAVE_GETENTROPY
#endif
#endif

#ifndef HAVE_GETENTROPY

#include <errno.h>
#include <stddef.h>
#include <unistd.h>

#if defined(__FreeBSD__) || defined(__NetBSD__)
#ifndef HAVE_SYSCTL_KERN_ARND
#define HAVE_SYSCTL_KERN_ARND
#endif
#endif

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__) || \
    defined(__linux__)   || defined(__hpux)     || defined(__sun)
#ifndef HAVE_DEV_URANDOM
#define HAVE_DEV_URANDOM
#endif
#endif

#if defined(_WIN32) || defined(_WIN64)
#ifndef HAVE_RTLGENRANDOM
#define HAVE_RTLGENRANDOM
#endif
#endif

#ifdef HAVE_SYSCTL_KERN_ARND
#include <sys/param.h>
#include <sys/sysctl.h>

static int getentropy_sysctl_kern_arnd(unsigned char *buf, size_t len) {
	int mib[2] = {CTL_KERN, KERN_ARND};
	int r, xlen;

	while (len > 0) {
		do {
			xlen = len;
			r = sysctl(&mib, 2, buf, &xlen, NULL, 0);
		} while (r == -1 && errno == EINTR);
		if (xlen < 1) { break; }
		buf += xlen;
		len -= xlen;
	}
	if (len == 0) { return 0; }
	return -1;
}
#endif  /* HAVE_SYSCTL_KERN_ARND */

#ifdef HAVE_DEV_URANDOM
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

static int getentropy_dev_urandom(unsigned char *buf, size_t len, const char* path) {
	int fd, flags, r;

	flags = O_RDONLY;
#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
	flags |= O_CLOEXEC;
#endif
	do {
		fd = open(path, flags, 0);
	} while (fd == -1 && errno == EINTR);
	if (fd != -1) {
#ifndef O_CLOEXEC
		fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
		while (len > 0) {
			do {
				r = read(fd, buf, len);
			} while (r == -1 && (errno == EINTR || errno == EAGAIN));
			if (r < 1) { break; }
			buf += r;
			len -= r;
		}
		close(fd);
		if (len == 0) { return 0; }
	}
	return -1;
}
#endif  /* HAVE_DEV_URANDOM */

#ifdef HAVE_RTLGENRANDOM
#include <windows.h>

/* CryptGenRandom thunks to RtlGenRandom, and the latter is easier to use.
 * http://blogs.msdn.com/b/michael_howard/archive/2005/01/14/353379.aspx
 *
 * CryptGenRandom:
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa379942(v=vs.85).aspx
 *
 * RtlGenRandom:
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa387694(v=vs.85).aspx
 */

static int getentropy_rtlgenrandom(unsigned char *buf, size_t len) {
	typedef BOOLEAN (APIENTRY *PFunc)(void*, ULONG);
	HMODULE hLib;
	PFunc pFunc;

	hLib = LoadLibrary("ADVAPI32.DLL");
	if (hLib) {
		pFunc = (PFunc)GetProcAddress(hLib, "SystemFunction036");
		if (pFunc) {
			if (pFunc(buf, len)) {
				FreeLibrary(hLib);
				return 0;
			}
		}
		FreeLibrary(hLib);
	}
	return -1;
}
#endif

int getentropy(void *buf, size_t len) {
	int saved_errno = errno;

#ifdef HAVE_RTLGENRANDOM
	if (getentropy_rtlgenrandom(buf, len) == 0) {
		errno = saved_errno;
		return 0;
	}
#endif

#ifdef HAVE_SYSCTL_KERN_ARND
	if (getentropy_sysctl_kern_arnd(buf, len) == 0) {
		errno = saved_errno;
		return 0;
	}
#endif

#ifdef HAVE_DEV_URANDOM
	if (getentropy_dev_urandom(buf, len, "/dev/urandom") == 0) {
		errno = saved_errno;
		return 0;
	}
	/* Solaris makes /dev/urandom a symlink to this. */
	if (getentropy_dev_urandom(buf, len, "/devices/pseudo/random@0:urandom") == 0) {
		errno = saved_errno;
		return 0;
	}
#endif

	errno = EIO;
	return -1;
}

#endif  /* !HAVE_GETENTROPY */

/* vim:set ts=8 sts=0 sw=8 noet: */

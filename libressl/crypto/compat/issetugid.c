/*
 * issetugid implementation
 * Public domain
 */

#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__)
#ifndef HAVE_ISSETUGID
#define HAVE_ISSETUGID
#endif
#endif

#ifndef HAVE_ISSETUGID
#if defined(__APPLE__)

/*
 * OS X has issetugid, but it is not fork-safe as of version 10.10.
 * See this Solaris report for test code that fails similarly:
 * http://mcarpenter.org/blog/2013/01/15/solaris-issetugid%282%29-bug
 */
int issetugid(void) { return 1; }

#elif defined(__hpux)

#include <stdio.h>
#include <unistd.h>
#include <sys/pstat.h>

/*
 * HP-UX does not have issetugid().
 * Use pstat_getproc() and check PS_CHANGEDPRIV bit of pst_flag. If this call
 * cannot be used, assume we must be running in a privileged environment.
 */
int issetugid(void) {
	struct pst_status buf;
	if (pstat_getproc(&buf, sizeof(buf), 0, getpid()) == 1 &&
	    !(buf.pst_flag & PS_CHANGEDPRIV)) {
		return 0;
	}
	return 1;
}

#elif defined(__linux__) && defined(HAVE_GETAUXVAL)

#include <errno.h>
#include <gnu/libc-version.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/auxv.h>

int issetugid(void)
{
	/*
	 * The API for glibc < 2.19 does not indicate if there is an error with
	 * getauxval. While it should not be the case that any 2.6 or greater
	 * kernel ever does not supply AT_SECURE, an emulated software environment
	 * might rewrite the aux vector.
	 *
	 * See https://sourceware.org/bugzilla/show_bug.cgi?id=15846
	 *
	 * Perhaps this code should just read the aux vector itself, so we have
	 * backward-compatibility and error handling in older glibc versions.
	 * info: http://lwn.net/Articles/519085/
	 *
	 */
	const char *glcv = gnu_get_libc_version();
	if (strverscmp(glcv, "2.19") >= 0) {
		errno = 0;
		if (getauxval(AT_SECURE) == 0) {
			if (errno != ENOENT) {
				return 0;
			}
		}
	}
	return 1;
}

#elif defined(_WIN32) || defined(_WIN64)

/*
 * Windows does not have a native setuid/setgid functionality.
 * A user must enter credentials each time a process elevates its
 * privileges.
 *
 * So, in theory, this could always return 0, given what I know currently.
 * However, it makes sense to stub out initially in 'safe' mode until we
 * understand more (and determine if any disabled functionality is actually
 * useful on Windows anyway).
 *
 * Future versions of this function that are made more 'open' should thoroughly
 * consider the case of this code running as a privileged service with saved
 * user credentials or privilege escalations by other means (e.g. the old
 * RunAsEx utility.)
 */
int issetugid(void) { return 1; }

#else

#warning "No issetugid defined for this platform."
int issetugid(void) { return 1; }

#endif
#endif  /* !HAVE_ISSETUGID */

/* vim:set ts=8 sts=0 sw=8 noet: */

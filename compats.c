#include "config.h"

#include "compats/unistd.h"
#ifndef HAVE_PIPE2
#include <fcntl.h>
int pipe2(int fildes[2], int flags) {
	int res = 0;
	if ((res = pipe(fildes)) < 0) return res;
	if ((fcntl(fildes[0], F_SETFD, flags)) < 0) return res;
	if ((fcntl(fildes[1], F_SETFD, flags)) < 0) return res;
	return 0;
}
#endif

#ifdef USE_NETBSD_GETENTROPY
#include <errno.h>
#include <sys/param.h>
#include <sys/sysctl.h>
int getentropy(void *buf, size_t buflen) {
	const int mib[] = { CTL_KERN, KERN_ARND };
	size_t n = buflen;
	if (buflen > 256) {
		errno = EIO;
		return -1;
	}
	if (sysctl(mib, (u_int)__arraycount(mib), buf, &n, NULL, 0) == -1)
		return -1;
	if (n != buflen) {
		errno = EIO;
		return -1;
	}
	return 0;
}
#endif

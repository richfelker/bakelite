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
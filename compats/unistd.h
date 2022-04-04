#ifndef __BAKELITE_COMPATS_UNISTD_H
# include <unistd.h>
# if !defined(HAVE_PIPE2)
int pipe2(int fildes[2], int flags);
# endif
# if defined(HAVE_GETENTROPY_SYS_RANDOM_H) 
#  include <sys/random.h>
# elif defined(USE_NETBSD_GETENTROPY)
int getentropy(void *buf, size_t buflen);
# endif
# define __BAKELITE_COMPATS_UNISTD_H
#endif

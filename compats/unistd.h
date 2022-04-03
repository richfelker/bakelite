#ifndef __BAKELITE_COMPATS_UNISTD_H
# include <unistd.h>
# ifndef HAVE_PIPE2
int pipe2(int fildes[2], int flags);
# endif
# ifdef HAVE_GETENTROPY_SYS_RANDOM_H
#  include <sys/random.h>
# endif
# define __BAKELITE_COMPATS_UNISTD_H
#endif
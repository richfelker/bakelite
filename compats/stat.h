#ifndef __BAKELITE_COMPAT_STAT_H
# include <sys/stat.h>
# if !defined(HAVE_STAT_AMC_TIM) && defined(HAVE_STAT_AMC_TIMESPEC)
#  define st_atim st_atimespec
#  define st_mtim st_mtimespec
#  define st_ctim st_ctimespec
# endif
# define __BAKELITE_COMPAT_STAT_H
#endif
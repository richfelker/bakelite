#ifndef BINHEX_H
#define BINHEX_H

#include <stddef.h>

char *bin2hex(char *hex, const unsigned char *bin, size_t n);
unsigned char *hex2bin(unsigned char *bin, const char *hex, size_t n);

#endif

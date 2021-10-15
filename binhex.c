#include <stdio.h>
#include "binhex.h"

char *bin2hex(char *hex, const unsigned char *bin, size_t n)
{
	for (int i=0; i<n; i++)
		sprintf(hex+2*i, "%.2x", bin[i]);
	return hex;
}

unsigned char *hex2bin(unsigned char *bin, const char *hex, size_t n)
{
	for (int i=0; i<n; i++) {
		int cnt = 0;
		sscanf(hex+2*i, "%2hhx%n", &bin[i], &cnt);
		if (cnt != 2) return 0;
	}
	return bin;
}

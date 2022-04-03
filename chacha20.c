#include <string.h>
#include <stdint.h>
#include "endian.h"
#include "chacha20.h"

static inline uint32_t rol(uint32_t x, int i)
{
	return (x<<i) | (x>>(32-i));
}

static inline void qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
	*a += *b; *d ^= *a; *d = rol(*d,16);
	*c += *d; *b ^= *c; *b = rol(*b,12);
	*a += *b; *d ^= *a; *d = rol(*d, 8);
	*c += *d; *b ^= *c; *b = rol(*b, 7);
}

void chacha20_block(uint32_t *x, const uint32_t *k, uint64_t b, uint64_t n)
{
	static const uint32_t c[4] = {
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	};

	for (int i=0; i < 4; i++) x[i] = c[i];
	for (int i=4; i < 12; i++) x[i] = k[i-4];
	x[12] = b;
	x[13] = b>>32;
	x[14] = n;
	x[15] = n>>32;

	for (int i=0; i<10; i++) {
		for (int j=0; j<4; j++)
			qr(x+j, x+4+j, x+8+j, x+12+j);
		for (int j=0; j<4; j++)
			qr(x+j, x+4+(j+1)%4, x+8+(j+2)%4, x+12+(j+3)%4);
	}

	for (int i=0; i < 4; i++) x[i] += c[i];
	for (int i=4; i < 12; i++) x[i] += k[i-4];
	x[12] += b;
	x[13] += b>>32;
	x[14] += n;
	x[15] += n>>32;
}

void chacha20_buf(unsigned char *buf, size_t len, const uint32_t *key, uint64_t nonce)
{
	size_t i, j;
	uint32_t x[16];

	// buf is assumed to be aligned and not have declared type,
	// and only to be otherwise accessed as the representation array.
	uint32_t *wbuf = (uint32_t *)buf;
	for (i=0; i*64<(len&-64); i++) {
		chacha20_block(x, key, i, nonce);
		for (j=0; j<16; j++) wbuf[i*16+j] ^= htole32(x[j]);
	}
	if (len & 63) {
		chacha20_block(x, key, i, nonce);
		for (j=0; j<16; j++) x[j] = htole32(x[j]);
		for (j=0; j<(len&63); j++)
			buf[i*64+j] ^= ((unsigned char *)x)[j];
	}
}

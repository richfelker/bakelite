#include <stdint.h>
#include <stdlib.h>
#include "crypto.h"
#include "bloom.h"

struct bloom *bloom_create(int k, size_t l)
{
	struct bloom *b = calloc(1, sizeof *b + l + 1);
	if (k>8) return 0;
	if (b) {
		b->bits[0] = k;
		b->l = l;
	}
	return b;
}

static int bloom_op(struct bloom *b, const unsigned char *h, int add)
{
	for (int i=0; i<b->bits[0]; i++) {
		uint64_t x = 0;
		for (int j=0; j<8; j++) {
			x |= (uint64_t)h[(5*i+j)%HASHLEN]<<(8*j);
		}
		size_t k = x % (8*b->l);
		if (add) b->bits[1+k/8] |= 1<<(k%8);
		else if (!(b->bits[1+k/8] & 1<<(k%8))) return 0;
	}
	return 1;
}

void bloom_add(struct bloom *b, const unsigned char *h)
{
	bloom_op(b, h, 1);
}

int bloom_query(const struct bloom *b, const unsigned char *h)
{
	return bloom_op((struct bloom *)b, h, 0);
}

void bloom_free(struct bloom *b)
{
	free(b);
}

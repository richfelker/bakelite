#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <endian.h>
#include "crypto.h"
#include "sha3.h"
#include "bloom.h"

struct bloom *bloom_create(int k, size_t l)
{
	struct bloom *b = calloc(1, sizeof *b + l + 32);
	if (k>8) return 0;
	if (b) {
		if (getentropy(b->bits, 31)) {
			free(b);
			return 0;
		}
		b->bits[31] = k;
		b->l = l;
	}
	return b;
}

static int bloom_op(struct bloom *b, const unsigned char *d, size_t n, int add)
{
	unsigned char *bits = b->bits + 32;
	int k = bits[-1];
	uint64_t hashes[256];
	sha3_ctx_t hc;
	sha3_init(&hc, 8*k);
	sha3_update(&hc, bits-32, 32);
	sha3_update(&hc, d, n);
	sha3_final(hashes, &hc);

	for (int i=0; i<k; i++) {
		size_t j = le64toh(hashes[i]) % (8*b->l);
		if (add) bits[j/8] |= 1<<(j%8);
		else if (!(bits[j/8] & 1<<(j%8))) return 0;
	}
	return 1;
}

void bloom_add(struct bloom *b, const unsigned char *d, size_t n)
{
	bloom_op(b, d, n, 1);
}

int bloom_query(const struct bloom *b, const unsigned char *d, size_t n)
{
	return bloom_op((struct bloom *)b, d, n, 0);
}

void bloom_free(struct bloom *b)
{
	free(b);
}

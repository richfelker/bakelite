#ifndef BLOOM_H
#define BLOOM_H

#include <stddef.h>

struct bloom {
	size_t l;
	unsigned char bits[];
};

struct bloom *bloom_create(int k, size_t l);
void bloom_add(struct bloom *b, const unsigned char *h);
int bloom_query(const struct bloom *b, const unsigned char *h);
void bloom_free(struct bloom *b);

#endif

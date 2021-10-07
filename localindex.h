#ifndef LOCALINDEX_H
#define LOCALINDEX_H

#include <stdio.h>
#include <sys/types.h>

struct localindex {
	struct timespec ts;
	FILE *txt;
	struct bloom *b;
	struct map *m;
	const struct map *devmap;
};

int localindex_getino(const struct localindex *idx, dev_t dev, ino_t ino, off_t block, unsigned char *result);
int localindex_getblock(const struct localindex *idx, const unsigned char *key, unsigned char *result);
int localindex_setino(const struct localindex *idx, dev_t dev, ino_t ino, off_t block, const unsigned char *val);
int localindex_setblock(const struct localindex *idx, const unsigned char *key, const unsigned char *val);
int localindex_create(struct localindex *idx, FILE *f, const struct timespec *ts, const struct map *devmap);
int localindex_open(struct localindex *idx, FILE *f, const struct map *devmap);
int localindex_null(struct localindex *idx);

#endif

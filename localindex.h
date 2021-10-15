#ifndef LOCALINDEX_H
#define LOCALINDEX_H

#include <stdio.h>
#include <sys/types.h>
#include "flatmap.h"

struct localindex {
	struct timespec ts;
	struct flatmap m;
	const struct map *devmap;
	long long obj_count;
	off_t ino_table, blk_table, meta_table, dep_table;
};

struct bloom;

int localindex_getino(const struct localindex *idx, dev_t dev, ino_t ino, unsigned char *result);
int localindex_getdep(const struct localindex *idx, dev_t dev, ino_t ino, off_t block, unsigned char *result);
int localindex_getblock(const struct localindex *idx, const unsigned char *key, unsigned char *result);
int localindex_setino(struct localindex *idx, dev_t dev, ino_t ino, const unsigned char *val);
int localindex_setdep(struct localindex *idx, dev_t dev, ino_t ino, off_t block, const unsigned char *val);
int localindex_setblock(struct localindex *idx, const unsigned char *key, const unsigned char *val);
void localindex_to_bloom(const struct localindex *idx, struct bloom *b);
int localindex_create(struct localindex *idx, int fd, const struct timespec *ts, const struct map *devmap);
int localindex_open(struct localindex *idx, int fd, const struct map *devmap);
int localindex_null(struct localindex *idx);
void localindex_close(struct localindex *idx);

#endif

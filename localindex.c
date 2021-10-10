#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include "sha3.h"
#include "bloom.h"
#include "crypto.h"
#include "map.h"
#include <unistd.h>

#include "localindex.h"

static char *bin2hex(char *hex, const unsigned char *bin, size_t n)
{
	for (int i=0; i<n; i++)
		sprintf(hex+2*i, "%.2x", bin[i]);
	return hex;
}

static unsigned char *hex2bin(unsigned char *bin, const char *hex, size_t n)
{
	for (int i=0; i<n; i++)
		sscanf(hex+2*i, "%2hhx", &bin[i]);
	return bin;
}

static size_t make_ino_label(char *label, size_t n, const struct localindex *idx, dev_t dev, ino_t ino, off_t block)
{
	char devbuf[2*sizeof(intmax_t)+1], *devname, sep = '/';
	snprintf(devbuf, sizeof devbuf, "%jx", (intmax_t)dev);
	devname = map_get(idx->devmap, devbuf);
	if (!devname) {
		devname = devbuf;
		sep = ':';
	}
	snprintf(label+4, n-4, "%s%c%ju%c%jd", devname, sep,
		(intmax_t)ino, block<0?0:'.', (intmax_t)block);
	size_t len = strlen(label+4);
	unsigned char hash[HASHLEN];
	sha3(label+4, len, hash, HASHLEN);
	memcpy(label, hash, 4);
	return len+4;
}

int localindex_getino(const struct localindex *idx, dev_t dev, ino_t ino, unsigned char *result)
{
	char label[100];
	size_t len = make_ino_label(label, sizeof label, idx, dev, ino, -1);
	off_t off = flatmap_get(&idx->m, idx->ino_table, label, len, result, result ? HASHLEN : 0);
	return off<0 ? -1 : !off ? 0 : 1;
}

int localindex_getdep(const struct localindex *idx, dev_t dev, ino_t ino, off_t block, unsigned char *result)
{
	char label[100];
	size_t len = make_ino_label(label, sizeof label, idx, dev, ino, block);
	off_t off = flatmap_get(&idx->m, idx->dep_table, label, len, result, result ? HASHLEN : 0);
	return off<0 ? -1 : !off ? 0 : 1;
}

int localindex_getblock(const struct localindex *idx, const unsigned char *key, unsigned char *result)
{
	off_t off = flatmap_get(&idx->m, idx->blk_table, key, HASHLEN, result, result ? HASHLEN : 0);
	return off<0 ? -1 : !off ? 0 : 1;
}

static int bloom_iter_func(const struct flatmap *m, off_t off, size_t kl, const void *k, void *ctx)
{
	unsigned char val[HASHLEN];
	ssize_t r = flatmap_read(m, val, HASHLEN, off);
	if (r != HASHLEN) return -1;
	bloom_add(ctx, val, HASHLEN);
	return 0;
}

void localindex_to_bloom(const struct localindex *idx, struct bloom *b)
{
	flatmap_iter(&idx->m, idx->ino_table, bloom_iter_func, b);
	flatmap_iter(&idx->m, idx->blk_table, bloom_iter_func, b);
}

int localindex_setino(struct localindex *idx, dev_t dev, ino_t ino, const unsigned char *val)
{
	char label[100];
	size_t len = make_ino_label(label, sizeof label, idx, dev, ino, -1);
	idx->obj_count++;
	return flatmap_set(&idx->m, idx->ino_table, label, len, val, HASHLEN) >= 0 ? 0 : -1;
}

int localindex_setdep(struct localindex *idx, dev_t dev, ino_t ino, off_t block, const unsigned char *val)
{
	char label[100];
	size_t len = make_ino_label(label, sizeof label, idx, dev, ino, block);
	return flatmap_set(&idx->m, idx->dep_table, label, len, val, HASHLEN) >= 0 ? 0 : -1;
}

int localindex_setblock(struct localindex *idx, const unsigned char *key, const unsigned char *val)
{
	idx->obj_count++;
	return flatmap_set(&idx->m, idx->blk_table, key, HASHLEN, val, HASHLEN) >= 0 ? 0 : -1;
}

int localindex_null(struct localindex *idx)
{
	FILE *tmp = tmpfile();
	flatmap_create(&idx->m, dup(fileno(tmp)), 0, 0, 4096);
	fclose(tmp);

	idx->devmap = map_create();
	if (!idx->devmap) return -1;
	return 0;
}

int localindex_create(struct localindex *idx, FILE *f, const struct timespec *ts, const struct map *devmap)
{
	idx->ts = *ts;
	idx->devmap = devmap;
	idx->obj_count = 0;

	if (flatmap_create(&idx->m, fileno(f), 0, 0, 128<<20) < 0)
		return -1;

	idx->ino_table = flatmap_newtable(&idx->m, 0, "inodes", 6);
	idx->dep_table = flatmap_newtable(&idx->m, 0, "deps", 4);
	idx->blk_table = flatmap_newtable(&idx->m, 0, "blocks", 6);
	idx->meta_table = flatmap_newtable(&idx->m, 0, "meta", 4);

	if (idx->ino_table < 0 || idx->dep_table < 0 || idx->blk_table < 0 || idx->meta_table < 0)
		return -1;

	char buf[256];
	buf[0] = snprintf(buf+1, sizeof buf-1, "%jd.%.9ld", (intmax_t)ts->tv_sec, ts->tv_nsec);

	if (flatmap_set(&idx->m, idx->meta_table, "timestamp", 9, buf, buf[0]+1) < 0)
		return -1;
	
	return 0;
}

int localindex_open(struct localindex *idx, FILE *f, const struct map *devmap)
{
	idx->devmap = devmap;
	idx->obj_count = -1; // unknown

	if (flatmap_open(&idx->m, fileno(f), 128<<20) < 0)
		return -1;

	idx->ino_table = flatmap_get(&idx->m, 0, "inodes", 6, 0, 0);
	idx->dep_table = flatmap_get(&idx->m, 0, "deps", 4, 0, 0);
	idx->blk_table = flatmap_get(&idx->m, 0, "blocks", 6, 0, 0);
	idx->meta_table = flatmap_get(&idx->m, 0, "meta", 4, 0, 0);

	if (idx->ino_table < 0 || idx->dep_table < 0 || idx->blk_table < 0 || idx->meta_table < 0)
		return -1;

	unsigned char tslen;
	char buf[256];
	off_t off = flatmap_get(&idx->m, idx->meta_table, "timestamp", 9, &tslen, 1);
	if (off<=0)
		return -1;
	flatmap_read(&idx->m, buf, tslen, off+1);
	buf[tslen] = 0;

	intmax_t t;
	long ns;
	if (sscanf(buf, "%jd.%9ld", &t, &ns) != 2)
		return -1;
	idx->ts.tv_sec = t;
	idx->ts.tv_nsec = ns;

	return 0;
}

#ifdef TEST
int main(int argc, char **argv)
{
	struct map *devmap = map_create();
	map_set(devmap, "0", "");

	struct localindex idx;
	localindex_open(&idx, stdin, devmap);
	if (argc==2) {
		unsigned char bin[HASHLEN], val[HASHLEN];
		hex2bin(bin, argv[1], HASHLEN);
		if (localindex_getblock(&idx, bin, val) > 0) {
			char hex[2*HASHLEN+1];
			bin2hex(hex, val, HASHLEN);
			printf("%s\n", hex);
		}
	} else {
	}
}
#endif

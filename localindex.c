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
	char devbuf[16], *devname, sep = '/';
	snprintf(devbuf, sizeof devbuf, "%jx", (intmax_t)dev);
	devname = map_get(idx->devmap, devbuf);
	if (!devname) {
		devname = devbuf;
		sep = ':';
	}
	snprintf(label, n, "%s%c%ju%c%jd", devname, sep,
		(intmax_t)ino, block<0?0:'.', (intmax_t)block);
	return strlen(label);
}

int localindex_getino(const struct localindex *idx, dev_t dev, ino_t ino, off_t block, unsigned char *result)
{
	char label[100];
	size_t len = make_ino_label(label, sizeof label, idx, dev, ino, block);
	unsigned char hash[HASHLEN+1];
	sha3(label, len, hash, HASHLEN);
	hash[HASHLEN] = 'b';
	off_t off = flatmap_get(&idx->m, hash, HASHLEN+(block>=0), result, result ? HASHLEN : 0);
	return off<0 ? -1 : !off ? 0 : 1;
}

int localindex_getblock(const struct localindex *idx, const unsigned char *key, unsigned char *result)
{
	off_t off = flatmap_get(&idx->m, key, HASHLEN, result, result ? HASHLEN : 0);
	return off<0 ? -1 : !off ? 0 : 1;
}

static void bloom_iter_func(off_t off, const unsigned char *k, const unsigned char *v, void *ctx)
{
	bloom_add(ctx, v, HASHLEN);
}

void localindex_to_bloom(const struct localindex *idx, struct bloom *b)
{
	flatmap_iter(&idx->m, bloom_iter_func, HASHLEN, HASHLEN, HASHLEN, b);
}

int localindex_setino(struct localindex *idx, dev_t dev, ino_t ino, off_t block, const unsigned char *val)
{
	char label[100];
	size_t len = make_ino_label(label, sizeof label, idx, dev, ino, block);
	unsigned char hash[HASHLEN+1];
	sha3(label, len, hash, HASHLEN);
	hash[HASHLEN] = 'b';
	if (block<0) idx->obj_count++;
	return flatmap_set(&idx->m, hash, HASHLEN+(block>=0), val, HASHLEN);
}

int localindex_setblock(struct localindex *idx, const unsigned char *key, const unsigned char *val)
{
	idx->obj_count++;
	return flatmap_set(&idx->m, key, HASHLEN, val, HASHLEN);
}

int localindex_null(struct localindex *idx)
{
	FILE *tmp = tmpfile();
	flatmap_create(&idx->m, dup(fileno(tmp)), 0, 0);
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

	if (flatmap_create(&idx->m, fileno(f), 0, 0) < 0)
		return -1;

	char buf[256];
	unsigned char hash[HASHLEN];
	size_t tslen = snprintf(buf, sizeof buf, "%jd.%.9ld\n", (intmax_t)ts->tv_sec, ts->tv_nsec);

	sha3("ts\0", 4, hash, HASHLEN);
	if (flatmap_set(&idx->m, hash, HASHLEN, (void *)buf, tslen+1) < 0)
		return -1;
	
	return 0;
}

int localindex_open(struct localindex *idx, FILE *f, const struct map *devmap)
{
	idx->devmap = devmap;
	idx->obj_count = -1; // unknown

	if (flatmap_open(&idx->m, fileno(f)) < 0)
		return -1;

	unsigned char hash[HASHLEN];
	sha3("ts\0", 4, hash, HASHLEN);
	off_t off = flatmap_get(&idx->m, hash, HASHLEN, 0, 0);
	if (off<=0)
		return -1;
	fseeko(f, off, SEEK_SET);
	intmax_t t;
	long ns;
	if (fscanf(f, "%jd.%9ld", &t, &ns) != 2)
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

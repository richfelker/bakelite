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
	return snprintf(label, n, "%s%c%ju%c%jd", devname, sep,
		(intmax_t)ino, block<0?0:'.', (intmax_t)block);
}

int localindex_getino(const struct localindex *idx, dev_t dev, ino_t ino, off_t block, unsigned char *result)
{
	char label[100];
	size_t len = make_ino_label(label, sizeof label, idx, dev, ino, block);
	unsigned char *p = map_get(idx->m, label);
	if (!p) return 0;
	if (result) memcpy(result, p, HASHLEN);
	return 1;
}

int localindex_getblock(const struct localindex *idx, const unsigned char *key, unsigned char *result)
{
	char hex[2*HASHLEN+1];
	unsigned char *p = map_get(idx->m, bin2hex(hex, key, HASHLEN));
	if (!p) return 0;
	if (result) memcpy(result, p, HASHLEN);
	return 1;
}

int localindex_setino(const struct localindex *idx, dev_t dev, ino_t ino, off_t block, const unsigned char *val)
{
	char label[100];
	size_t len = make_ino_label(label, sizeof label, idx, dev, ino, block);
	unsigned char hash[HASHLEN+1];
	sha3(label, len, hash, sizeof hash);
	hash[HASHLEN] = 'i';
	char hexval[2*HASHLEN+1];
	if (fprintf(idx->txt, "%s %s\n", label, bin2hex(hexval, val, HASHLEN)) < 0) return -1;
	char *p = malloc(HASHLEN);
	if (!p) return -1;
	memcpy(p, val, HASHLEN);
	return map_set(idx->m, label, p);
}

int localindex_setblock(const struct localindex *idx, const unsigned char *key, const unsigned char *val)
{
	char hexkey[2*HASHLEN+1], hexval[2*HASHLEN+1];
	if (fprintf(idx->txt, "%s %s\n", bin2hex(hexkey, key, HASHLEN), bin2hex(hexval, val, HASHLEN)) < 0) return -1;
	char *p = malloc(HASHLEN);
	if (!p) return -1;
	memcpy(p, val, HASHLEN);
	return map_set(idx->m, hexkey, p);
}

int localindex_null(struct localindex *idx)
{
	idx->devmap = idx->m = map_create();
	if (!idx->m) return -1;
	return 0;
}

int localindex_create(struct localindex *idx, FILE *f, const struct timespec *ts, const struct map *devmap)
{
	idx->m = map_create();
	if (!idx->m) goto fail;

	idx->txt = f;
	idx->ts = *ts;
	idx->devmap = devmap;
	
	fprintf(f, "timestamp %lld.%.9ld\n", (long long)ts->tv_sec, ts->tv_nsec);
	fprintf(f, "index\n");

	return 0;
fail:
	if (idx->m) map_destroy(idx->m);
	return -1;
}

int localindex_open(struct localindex *idx, FILE *f, const struct map *devmap)
{
	idx->m = map_create();
	if (!idx->m) goto fail;
	idx->devmap = devmap;

	char buf[256];
	while (fgets(buf, sizeof buf, f)) {
		if (!strncmp(buf, "timestamp ", 10)) {
			long long t, ns;
			sscanf(buf+10, "%lld.%lld", &t, &ns);
			idx->ts.tv_sec = t;
			idx->ts.tv_nsec = ns;
		} else if (!strncmp(buf, "index", 5)) {
			break;
		}
	}

	while (fgets(buf, sizeof buf, f)) {
		int p1 = -1, p2 = -1;
		sscanf(buf, "%*s%n%*s%n", &p1, &p2);
		if (p2 < 0) goto fail;
		buf[p1] = buf[p2] = 0;
		unsigned char *val = malloc(HASHLEN);
		hex2bin(val, buf+p1+1, HASHLEN);
		if (map_set(idx->m, buf, val) < 0) goto fail;
	}
	if (ferror(f)) goto fail;
	return 0;
fail:
	if (idx->m) map_destroy(idx->m);
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

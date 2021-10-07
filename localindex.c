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
	char hexval[2*HASHLEN+1];
	if (fprintf(idx->txt, "%s %s\n", label, bin2hex(hexval, val, HASHLEN)) < 0) return -1;
	if (block<0) idx->obj_count++;
	return flatmap_set(&idx->m, hash, HASHLEN+(block>=0), val, HASHLEN);
}

int localindex_setblock(struct localindex *idx, const unsigned char *key, const unsigned char *val)
{
	char hexkey[2*HASHLEN+1], hexval[2*HASHLEN+1];
	if (fprintf(idx->txt, "%s %s\n", bin2hex(hexkey, key, HASHLEN), bin2hex(hexval, val, HASHLEN)) < 0) return -1;
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
	FILE *tmp = tmpfile();
	flatmap_create(&idx->m, dup(fileno(tmp)), 0, 0);
	fclose(tmp);

	idx->txt = f;
	idx->ts = *ts;
	idx->devmap = devmap;
	idx->obj_count = 0;
	
	fprintf(f, "timestamp %lld.%.9ld\n", (long long)ts->tv_sec, ts->tv_nsec);
	fprintf(f, "index\n");

	return 0;
fail:
	return -1;
}

int localindex_open(struct localindex *idx, FILE *f, const struct map *devmap)
{
	FILE *tmp = tmpfile();
	flatmap_create(&idx->m, dup(fileno(tmp)), 0, 0);
	fclose(tmp);

	idx->devmap = devmap;
	idx->obj_count = -1; // unknown

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

		unsigned char key[HASHLEN+1];
		unsigned char val[HASHLEN];
		size_t kl;

		hex2bin(val, buf+p1+1, HASHLEN);

		if (p1==2*HASHLEN) {
			hex2bin(key, buf, HASHLEN);
			kl = HASHLEN;
		} else {
			sha3(buf, p1, key, HASHLEN);
			key[HASHLEN] = 'b';
			kl = HASHLEN+!!strchr(buf, '.');
		}
		if (flatmap_set(&idx->m, key, kl, val, HASHLEN)<0)
			goto fail;
	}
	if (ferror(f)) goto fail;
	return 0;
fail:
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

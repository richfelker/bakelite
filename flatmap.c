#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "flatmap.h"

#include <stdio.h>

static ssize_t pread_wrap(int fd, void *buf, size_t len, off_t off)
{
	for (size_t cnt, i=0; i<len; i+=cnt) {
		cnt = pread(fd, (char *)buf + i, len-i, off+i);
		if (cnt <= 0) {
			if (!cnt) return i;
			return -1;
		}
	}
	return len;
}

static ssize_t pwrite_wrap(int fd, const void *buf, size_t len, off_t off)
{
	for (size_t cnt, i=0; i<len; i+=cnt) {
		cnt = pwrite(fd, (const char *)buf + i, len-i, off+i);
		if (cnt < 0) return -1;
	}
	return len;
}

ssize_t flatmap_read(const struct flatmap *m, void *buf, size_t len, off_t off)
{
	off_t max = m->mmlen > m->maxoff ? m->maxoff : m->mmlen;
	if (off >= max || len > max - off)
		return pread_wrap(m->fd, buf, len, off);
	memcpy(buf, m->mm + off, len);
	return len;
}

ssize_t flatmap_write(struct flatmap *m, const void *buf, size_t len, off_t off)
{
	if (m->mode != O_RDWR) {
		errno = EBADF;
		return -1;
	}
	off_t max = m->mmlen > m->maxoff ? m->maxoff : m->mmlen;
	if (off < max && len < max - off) {
		memcpy(m->mm + off, buf, len);
		return len;
	}
	ssize_t r = pwrite_wrap(m->fd, buf, len, off);
	if (r >= 0 && off+r > m->maxoff) m->maxoff = off+r;
	return r;
}

#define N(k,i) ( (((unsigned char *)k)[(i)/2]>>4*((i)%2)) % 16 )

static int64_t search(const struct flatmap *m, off_t root, const unsigned char *k, size_t l, unsigned char *tail, size_t *pdepth, off_t *plast)
{
	if (l > 255) return -1;
	off_t off = 0;
	int64_t next = root ? root : m->off0;
	size_t i;
	ssize_t cnt;

	for (i=0; i<=2*l; i++) {
		int c = i<2*l ? N(k,i) : 16;
		off = next + c * sizeof next;
		cnt = flatmap_read(m, &next, sizeof next, off);
		if (cnt != sizeof next) return -1;
		next = le64toh(next);
		if (next < 0) break;
	}
	if (pdepth) *pdepth = i;
	if (plast) *plast = off;

	if (next == -1) return 0;
	next &= INT64_MAX;
	cnt = flatmap_read(m, tail, l+1+1, next); // one extra char to update table
	if (cnt < 0) return cnt;
	if (tail[0]==l && cnt < l+2) return -1; // truncated file?

	return next;
}

off_t flatmap_get(const struct flatmap *m, off_t root, const void *k, size_t kl, void *val, size_t vl)
{
	unsigned char tail[257];
	int64_t off = search(m, root, k, kl, tail, 0, 0);
	if (off<0) return -1;
	if (!off || tail[0] != kl || memcmp(k, tail+1, kl))
		return 0;
	if (flatmap_read(m, val, vl, off+tail[0]+1) != vl)
		return -1;
	return off+tail[0]+1;
}

off_t flatmap_set(struct flatmap *m, off_t root, const void *k, size_t kl, const void *val, size_t vl)
{
	unsigned char tail[257];
	int64_t last;
	size_t depth;
	int64_t off = search(m, root, k, kl, tail, &depth, &last);
	off_t nextpos = lseek(m->fd, 0, SEEK_END);
	size_t i=0, j;
	uint64_t table[17];
	memset(table, -1, sizeof table);

	if (off < 0) return -1;

	if (off > 0) {
		/* Measure matching prefix length. */
		for (i=0; i<2*kl && i<2*tail[0] && N(k,i) == N(tail+1,i); i++);
		i -= depth;

		/* If we found the key already present, we will just replace it;
		 * there is no matching prefix to split at. */
		if (tail[0] == kl && i+depth==2*kl) {
			off = 0;
		}
	}

	off_t new = nextpos;
	unsigned char buf[256];
	buf[0] = kl;
	memcpy(buf+1, k, kl);
	if (flatmap_write(m, buf, kl+1, nextpos) < 0)
		return -1;
	nextpos += kl+1;
	if (!val) {
		// if val is null, only write a final null byte to leave
		// a gap of length vl for the caller to fill later.
		val = "";
		nextpos += vl-1;
		vl = 1;
	}
	if (flatmap_write(m, val, vl, nextpos) < 0)
		return -1;
	nextpos += vl;

	if (off == 0) {
		if (flatmap_write(m, &(uint64_t){ htole64(new|INT64_MIN) }, 8, last) < 0)
			return -1;
		return new+1+kl;
	}

//printf("prefix %d\n", (int)(depth+i));
//printf("depth=%zd i=%zu kl=%zu\n", depth, i, kl);
	off_t split = nextpos;
	for (j=0; j+1<i; j++) {
		int c = N(tail+1,depth+1+j);
		table[c] = htole64(nextpos + sizeof table);
		if (flatmap_write(m, table, sizeof table, nextpos) < 0)
			return -1;
		table[c] = -1;
		nextpos += sizeof table;
	}
	table[depth+i<2*kl ? N(k,depth+i) : 16] = htole64(new|INT64_MIN);
//printf("[%c]\n", tail[1+i]);
	table[depth+i<2*tail[0] ? N(tail+1,depth+i) : 16] = htole64(off|INT64_MIN);
	if (flatmap_write(m, table, sizeof table, nextpos) < 0)
		return -1;
	if (flatmap_write(m, &(uint64_t){ htole64(split) }, 8, last) < 0)
		return -1;
	return new+1+kl;
}

off_t flatmap_newtable(struct flatmap *m, off_t parent, const void *k, size_t kl)
{
	uint64_t table[17];
	memset(table, -1, sizeof table);
	return flatmap_set(m, parent, k, kl, table, sizeof table);
}

static int do_iter(const struct flatmap *m, off_t off,
	int (*f)(const struct flatmap *, off_t, size_t, const void *, void *),
	unsigned char *key, int depth, void *ctx)
{
	uint64_t table[17];
	if (flatmap_read(m, table, sizeof table, off) != sizeof table)
		return -1;
	for (int i=0; i<17; i++) {
		int64_t p = le64toh(table[i]);
		if (p & INT64_MIN) {
			p &= INT64_MAX;
			if (p == INT64_MAX) continue;
			ssize_t r = flatmap_read(m, key, 257, p);
			if (r<1 || r<key[0])
				return -1;
			if (f(m, p+1+key[0], key[0], key+1, ctx) < 0)
				return -1;
		} else {
			if (!depth) return -1;
			if (do_iter(m, p, f, key, depth-1, ctx) < 0)
				return -1;
		}
	}
	return 0;
}

int flatmap_iter(const struct flatmap *m, off_t root,
	int (*f)(const struct flatmap *, off_t, size_t, const void *, void *), void *ctx)
{
	unsigned char key[257];
	if (!root) root = m->off0;
	return do_iter(m, root, f, key, 256, ctx);
}

struct header {
	char magic[16];
	uint64_t start;
};

#define MAGIC "flatmap\xff\2\0\0\0\0\0\0\0"

int flatmap_create(struct flatmap *m, int fd, const void *comment, size_t comment_len, size_t mmsize)
{
	if (lseek(fd, 0, SEEK_END) != 0) return -1;
	struct header header = {
		.magic = MAGIC,
		.start = htole64(sizeof header + comment_len)
	};
	pwrite_wrap(fd, &header, sizeof header, 0);
	if (comment_len) pwrite_wrap(fd, comment, comment_len, sizeof header);
	uint64_t table[17];
	memset(table, -1, sizeof table);
	pwrite_wrap(fd, table, sizeof table, sizeof header + comment_len);
	m->mode = O_RDWR;
	m->mm = mmap(0, mmsize, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	m->mmlen = (m->mm == MAP_FAILED) ? 0 : mmsize;
	m->fd = fd;
	m->off0 = sizeof header + comment_len;
 	m->maxoff = 0;
	return 0;
}

int flatmap_open(struct flatmap *m, int fd, size_t mmsize)
{
	struct header header;
	ssize_t cnt = pread_wrap(fd, &header, sizeof header, 0);
	if (cnt < 0) return cnt;
	if (cnt < sizeof header || memcmp(header.magic, MAGIC, sizeof header.magic) ||
	    le64toh(header.start) >= 0x100000000) {
		errno = EINVAL;
		return -1;
	}
	m->mode = fcntl(fd, F_GETFL) & O_ACCMODE;
	m->mm = mmap(0, mmsize, PROT_READ | (m->mode==O_RDWR ? PROT_WRITE : 0), MAP_SHARED, fd, 0);
	m->mmlen = (m->mm == MAP_FAILED) ? 0 : mmsize;
	m->fd = fd;
	m->off0 = le64toh(header.start);
	struct stat st;
	m->maxoff = fstat(fd, &st) ? 0 : st.st_size;
	return 0;
}

void flatmap_close(struct flatmap *m)
{
	munmap(m->mm, m->mmlen);
}

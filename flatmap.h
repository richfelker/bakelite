#ifndef FLATMAP_H
#define FLATMAP_H

#include <sys/types.h>

struct flatmap {
	int fd;
	off_t off0, maxoff;
	unsigned char *mm;
	size_t mmlen;
};

ssize_t flatmap_read(const struct flatmap *m, void *buf, size_t len, off_t off);
ssize_t flatmap_write(struct flatmap *m, const void *buf, size_t len, off_t off);
off_t flatmap_get(const struct flatmap *m, const unsigned char *k, size_t kl, void *val, size_t vl);
off_t flatmap_set(struct flatmap *m, const unsigned char *k, size_t kl, const void *val, size_t vl);
int flatmap_create(struct flatmap *m, int fd, const void *comment, size_t comment_len, size_t mmsize);
int flatmap_open(struct flatmap *m, int fd, size_t mmsize);

int flatmap_iter(const struct flatmap *m,
	void (*f)(off_t, const unsigned char *, const unsigned char *, void *),
	size_t kl, size_t vl, int depth, void *ctx);

#endif

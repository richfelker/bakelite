#ifndef FLATMAP_H
#define FLATMAP_H

#include <sys/types.h>

struct flatmap {
	int fd;
	off_t off0;
};

off_t flatmap_get(const struct flatmap *m, const unsigned char *k, size_t kl, void *val, size_t vl);
int flatmap_set(struct flatmap *m, const unsigned char *k, size_t kl, const void *val, size_t vl);
int flatmap_create(struct flatmap *m, int fd, const void *comment, size_t comment_len);
int flatmap_open(struct flatmap *m, int fd);

int flatmap_iter(const struct flatmap *m,
	void (*f)(off_t, const unsigned char *, const unsigned char *, void *),
	size_t kl, size_t vl, int depth, void *ctx);

#endif

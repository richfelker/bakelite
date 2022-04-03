#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <search.h>

struct map {
	void *root;
};

struct pair {
	char *key;
	void *val;
	char buf[];
};

static int cmp(const void *a0, const void *b0)
{
	const struct pair *a = a0, *b = b0;
	return strcmp(a->key, b->key);
}

struct map *map_create()
{
	return calloc(1, sizeof *map_create());
}

void map_destroy(struct map *map)
{
	while (map->root)
		tdelete(*(void **)map->root, &map->root, cmp);
}

void *map_get(const struct map *map, const char *key)
{
	struct pair pair = { .key = (char *)key };
	void **node = tfind(&pair, &map->root, cmp);
	if (!node) return 0;
	struct pair *p = *node;
	return p->val;
}

int map_set(struct map *map, const char *key, void *val)
{
	struct pair pair = { .key = (char *)key };
	void **node  = tsearch(&pair, &map->root, cmp);
	if (!node) return -1;
	struct pair *p = *node;
	if (p == &pair) {
		p = malloc(sizeof *p + strlen(key) + 1);
		if (!p) {
			tdelete(&pair, &map->root, cmp);
			return -1;
		}
		strcpy(p->key=p->buf, key);
		*node = p;
	}
	p->val = val;
	return 0;
}

static _Thread_local void (*iter_act)(const char *, const void *, void *ctx);
static void *iter_ctx;

static void action_wrap(const void *vnode, VISIT order, int depth)
{
	if (order != postorder && order != leaf) return;
	struct pair *pair = *(void **)vnode;
	iter_act(pair->key, pair->val, iter_ctx);
}

void map_iter(const struct map *map, void (*act)(const char *, const void *, void *), void *ctx)
{
	void (*old_act)(const char *, const void *, void *) = iter_act;
	void *old_ctx = iter_ctx;
	iter_act = act;
	iter_ctx = ctx;
	twalk(map->root, action_wrap);
	iter_act = old_act;
	iter_ctx = old_ctx;
}

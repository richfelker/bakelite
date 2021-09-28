#ifndef MAP_H
#define MAP_H

struct map;
struct map *map_create(void);
void map_destroy(struct map *);
void *map_get(const struct map *, const char *);
int map_set(struct map *, const char *, void *);
void map_iter(const struct map *, void (*)(const char *, const void *, void *), void *);

#endif

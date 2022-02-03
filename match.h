#ifndef MATCH_H
#define MATCH_H

struct matcher;

struct matcher *matcher_from_file(FILE *);

int matcher_matches(struct matcher *, const char *);

#endif

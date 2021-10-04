#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include "crypto.h"
#include "bloom.h"
#include "sha3.h"

int hex2hash(unsigned char *h, const char *s)
{
	for (int n, i=0; i<HASHLEN; i++) {
		if (sscanf(s+2*i, "%2hhx%n", h+i, &n) != 1 || n != 2)
			return -1;
	}
	return 0;
}


int prune_bloom(struct bloom **filters, size_t nfilters)
{
	DIR *d = opendir(".");
	struct dirent *de;
	while ((de = readdir(d))) {
		if (strspn(de->d_name, "0123456789abcdef") != 2*HASHLEN
		    || de->d_name[2*HASHLEN]) {
			continue;
		}
		unsigned char hash[HASHLEN];
		hex2hash(hash, de->d_name);
		for (int i=0; i<nfilters; i++) {
			if (bloom_query(filters[i], hash, HASHLEN)) {
				printf("keep %s\n", de->d_name);
				goto keep;
			}
		}
		printf("drop %s\n", de->d_name);
keep:
		;
	}
	return 0;
}


static void prune_usage(char *progname)
{
	printf("usage: %s backup [options] <indexdir>\n", progname);
}

int prune_main(int argc, char **argv, char *progname)
{
	int c;
	void (*usage)(char *) = prune_usage;

	while ((c=getopt(argc, argv, "")) >= 0) switch (c) {
	case '?':
		usage(progname);
		return 1;
	}

	unsigned char hash[HASHLEN];

	FILE *f = fopen(argv[optind], "rbe");
	struct stat st;
	fstat(fileno(f), &st);
	struct bloom *b = malloc(sizeof *b + st.st_size);
	b->l = st.st_size - 32;
	fread(b->bits, 1, st.st_size, f);
	fclose(f);
	sha3(b->bits, st.st_size, hash, HASHLEN);
	bloom_add(b, hash, HASHLEN);

	prune_bloom(&b, 1);
	return 0;
}

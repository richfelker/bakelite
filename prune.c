#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include "compats/unistd.h"
#include "compats/stat.h"
#include <fcntl.h>
#include <errno.h>
#include "crypto.h"
#include "bloom.h"
#include "sha3.h"
#include "binhex.h"
#include "store.h"

int prune_in_dir(DIR *d, const char *dirname, struct bloom **filters, size_t nfilters, int list_keeps)
{
	struct dirent *de;
	while ((de = readdir(d))) {
		unsigned char hash[HASHLEN];
		if (!hex2bin(hash, de->d_name, HASHLEN))
			continue;
		for (int i=0; i<nfilters; i++) {
			if (bloom_query(filters[i], hash, HASHLEN)) {
				if (list_keeps)
					printf("%s%s\n", dirname, de->d_name);
				goto keep;
			}
		}
		if (!list_keeps) printf("%s%s\n", dirname, de->d_name);
keep:
		;
	}
	return 0;
}

int do_prune(int base_fd, struct bloom **filters, size_t nfilters, int list_keeps)
{
	for (int i=0; i<4096; i++) {
		char dirname[BLOBNAME_SIZE];
		snprintf(dirname, sizeof dirname, "objects/%.3x/", i);
		int fd = openat(base_fd, dirname, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
		if (fd < 0) {
			if (errno != ENOENT) {
				fprintf(stderr, "error opening %s: ", dirname);
				perror(0);
			}
			continue;
		}
		DIR *d = fdopendir(fd);
		if (!d) {
			fprintf(stderr, "error opening %s: ", dirname);
			perror(0);
			close(fd);
			continue;
		}
		prune_in_dir(d, dirname, filters, nfilters, list_keeps);
		closedir(d);
	}
	return 0;
}

static void prune_usage(char *progname)
{
	printf("usage: %s prune [options] <summary_file> ...\n", progname);
}

int prune_main(int argc, char **argv, char *progname)
{
	int c, d;
	int list_keeps = 0;
	void (*usage)(char *) = prune_usage;

	while ((c=getopt(argc, argv, "v")) >= 0) switch (c) {
	case 'v':
		list_keeps = 1;
		break;
	case '?':
		usage(progname);
		return 1;
	}

	if (optind == argc) {
		usage(progname);
		return 1;
	}

	int nblooms = argc-optind+1;
	struct bloom **b = calloc(sizeof (struct bloom *), nblooms);

	char *z = strrchr(argv[optind], '/');
	if (z) {
		*z = 0;
		d = open(argv[optind], O_RDONLY|O_DIRECTORY|O_CLOEXEC);
		*z = '/';
		if (d<0) {
			perror("opening directory");
			return 1;
		}
	} else {
		d = AT_FDCWD;
	}

	b[0] = bloom_create(8, 16*(argc-optind));

	for (int i=optind; i<argc; i++) {
		int j = i-optind + 1;
		FILE *f = fopen(argv[i], "rbe");
		if (!f) {
			fprintf(stderr, "error opening %s: ", argv[i]);
			perror(0);
			return 1;
		}
		char buf[256];
		unsigned char bloom_hash[HASHLEN];
		while (fgets(buf, sizeof buf, f) && strncmp(buf, "bloom ", 6));
		if (feof(f) || !hex2bin(bloom_hash, buf+6, HASHLEN)) {
			fprintf(stderr, "no bloom filter found in %s\n", argv[i]);
			return 1;
		}
		fclose(f);
		char bloom_filename[BLOBNAME_SIZE];
		gen_blob_name(bloom_filename, bloom_hash);
		int fd = openat(d, bloom_filename, O_RDONLY|O_CLOEXEC);
		f = fdopen(fd, "rb");
		if (fd<0 || !f) {
			fprintf(stderr, "error opening bloom filter for %s (%s): ",
				argv[i], bloom_filename);
			perror(0);
			return 1;
		}
		struct stat st;
		fstat(fd, &st);
		b[j] = malloc(sizeof *b + st.st_size);
		b[j]->l = st.st_size - 32;
		fread(b[j]->bits, 1, st.st_size, f);
		fclose(f);
		unsigned char computed_hash[HASHLEN];
		sha3(b[j]->bits, st.st_size, computed_hash, HASHLEN);
		if (memcmp(computed_hash, bloom_hash, HASHLEN)) {
			fprintf(stderr, "hash mismatch in bloom filter for %s (%s)\n",
				argv[i], bloom_filename);
			return 1;
		}
		bloom_add(b[0], bloom_hash, HASHLEN);
	}

	do_prune(d, b, nblooms, list_keeps);
	return 0;
}

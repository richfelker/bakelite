#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "x25519.h"

static void genkey_usage(char *progname)
{
	printf("usage: %s genkey <file>\n", progname);
}

int genkey_main(int argc, char **argv, char *progname)
{
	int c;
	void (*usage)(char *) = genkey_usage;

	while ((c=getopt(argc, argv, "")) >= 0) switch (c) {
	case '?':
		usage(progname);
		return 1;
	}

	if (argc-optind != 1) {
		usage(progname);
		return 1;
	}

	const char *name = argv[optind];

	unsigned char key[32];
	if (getentropy(key, sizeof key)) {
		perror("getentropy");
		return 1;
	}

	int fd = open(name, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
	if (fd < 0) {
		fprintf(stderr, "error creating file: %s", name);
		perror(0);
		return 1;
	}
	FILE *f = fdopen(fd, "wb");
	if (!f) {
		close(fd);
		perror("fdopen");
		return 1;
	}
	if (fwrite(key, 1, sizeof key, f) != sizeof key || fflush(f)) {
		perror("error writing key file");
		return 1;
	}
	fclose(f);
	return 0;
}

static void pubkey_usage(char *progname)
{
	printf("usage: %s pubkey <secret_key_file> > <public_key_file>\n", progname);
}

int pubkey_main(int argc, char **argv, char *progname)
{
	int c;
	void (*usage)(char *) = pubkey_usage;

	while ((c=getopt(argc, argv, "")) >= 0) switch (c) {
	case '?':
		usage(progname);
		return 1;
	}

	if (argc-optind != 1) {
		usage(progname);
		return 1;
	}

	const char *name = argv[optind];

	unsigned char key[32];

	int fd = open(name, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "error opening file: %s", name);
		perror(0);
		return 1;
	}
	FILE *f = fdopen(fd, "rb");
	if (!f) {
		close(fd);
		perror("fdopen");
		return 1;
	}
	if (fread(key, 1, sizeof key, f) != sizeof key || getc(f)!=EOF) {
		fprintf(stderr, "invalid key file %s: musl be %zu bytes", name, sizeof key);
		return 1;
	}
	fclose(f);

	x25519_scalarmult(key, key, (unsigned char[32]){9});
	if (fwrite(key, 1, sizeof key, stdout) || fflush(stdout)) {
		perror("error writing output");
		return 1;
	}

	return 0;
}

static void init_usage(char *progname)
{
	printf("usage: %s init [-k <pubkeyfile>] <indexdir> <rootdir>\n", progname);
}

int init_main(int argc, char **argv, char *progname)
{
	const char *keyfile = 0;
	int c, fd, d;
	FILE *f;
	unsigned char key[32];
	void (*usage)(char *) = init_usage;

	while ((c=getopt(argc, argv, "k:")) >= 0) switch (c) {
	case 'k':
		keyfile = optarg;
		break;
	case '?':
		usage(progname);
		return 1;
	}

	if (argc-optind != 2) {
		usage(progname);
		return 1;
	}

	const char *indexdir = argv[optind];
	const char *rootdir = argv[optind+1];

	if (!keyfile) {
		fprintf(stderr, "recipient key file (-k) is mandatory\n");
		return 1;
	}
	fd = open(keyfile, O_RDONLY|O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "cannot open key file %s: ", keyfile);
		perror(0);
		return 1;
	}
	f = fdopen(fd, "rb");
	if (!f) {
		close(fd);
		perror("fdopen");
		return 1;
	}
	if (fread(key, 1, sizeof key, f) != sizeof key || getc(f) != EOF) {
		fprintf(stderr, "invalid key file %s: musl be %zu bytes", keyfile, sizeof key);
		return 1;
	}
	fclose(f);

	if (mkdir(indexdir, 0700)) {
		fprintf(stderr, "cannot create directory %s: ", indexdir);
		perror(0);
		return 1;
	}
	d = open(indexdir, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
	if (d < 0) {
		fprintf(stderr, "cannot open directory %s: ", indexdir);
		perror(0);
		return 1;
	}
	if (symlinkat(rootdir, d, "root")) {
		perror("cannot make root symlink");
		return 1;
	}
	if (mkdirat(d, "devices", 0700)) {
		perror("cannot make devices directory");
		return 1;
	}
	fd = openat(d, "pubkey", O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
	if (fd < 0) {
		perror("error creating key file");
		return 1;
	}
	f = fdopen(fd, "wb");
	if (!f) {
		close(fd);
		perror("fdopen");
		return 1;
	}
	if (fwrite(key, 1, sizeof key, f) != sizeof(key) || fflush(f)) {
		fclose(f);
		perror("error writing key file");
		return 1;
	}
	fclose(f);
	close(d);
	return 0;
}

static void commit_usage(char *progname)
{
	printf("usage: %s commit <indexdir>\n", progname);
}

int commit_main(int argc, char **argv, char *progname)
{
	int c;
	void (*usage)(char *) = commit_usage;

	while ((c=getopt(argc, argv, "")) >= 0) switch (c) {
	case '?':
		usage(progname);
		return 1;
	}

	if (argc-optind != 1) {
		usage(progname);
		return 1;
	}

	const char *indexdir = argv[optind];

	int d = open(indexdir, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
	if (d < 0) {
		fprintf(stderr, "cannot open index directory %s: ", indexdir);
		perror(0);
		return 1;
	}

	if (renameat(d, "index.pending", d, "index")) {
		close(d);
		if (errno == ENOENT) {
			printf("no uncommitted backup index\n");
			return 0;
		}
		perror("rename");
		return 1;
	}

	close(d);
	printf("successfully committed\n");
	return 0;
}

static void abort_usage(char *progname)
{
	printf("usage: %s abort <indexdir>\n", progname);
}

int abort_main(int argc, char **argv, char *progname)
{
	int c;
	void (*usage)(char *) = abort_usage;

	while ((c=getopt(argc, argv, "")) >= 0) switch (c) {
	case '?':
		usage(progname);
		return 1;
	}

	if (argc-optind != 1) {
		usage(progname);
		return 1;
	}

	const char *indexdir = argv[optind];

	int d = open(indexdir, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
	if (d < 0) {
		fprintf(stderr, "cannot open index directory %s: ", indexdir);
		perror(0);
		return 1;
	}

	if (unlinkat(d, "index.pending", 0)) {
		close(d);
		if (errno == ENOENT) {
			printf("no uncommitted backup index\n");
			return 0;
		}
		perror("unlink");
		return 1;
	}

	close(d);
	printf("uncommitted backup aborted\n");
	return 0;
}

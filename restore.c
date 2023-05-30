#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include "chacha20.h"
#include "x25519.h"
#include "crypto.h"
#include "sha3.h"
#include "map.h"
#include "binhex.h"
#include "store.h"
#include "localindex.h"

struct decrypt_context {
	const unsigned char *rcpt_secret;
	struct map *ephemeral_map;
};

static int dupe(int fd)
{
	return fcntl(fd, F_DUPFD_CLOEXEC, 0);
}

void *load_and_decrypt_file(size_t *size, unsigned char *computed_hash, int dfd, const char *name, struct decrypt_context *dc)
{
	int fd = openat(dfd, name, O_RDONLY|O_CLOEXEC);
	if (fd<0) return 0;
	struct stat st;
	if (fstat(fd, &st) || st.st_size > PTRDIFF_MAX) {
		close(fd);
		return 0;
	}
	unsigned char *buf = malloc(st.st_size+64);
	FILE *f = fdopen(fd, "rb");

	sha3_ctx_t h;
	sha3_init(&h, HASHLEN);

	unsigned char ephemeral_public[32];
	fread(ephemeral_public, 1, 32, f);
	sha3_update(&h, ephemeral_public, sizeof ephemeral_public);

	uint64_t nonce;
	fread(&nonce, 1, 8, f);
	sha3_update(&h, &nonce, sizeof nonce);
	nonce = le64toh(nonce);

	char ephemeral_hex[65];
	bin2hex(ephemeral_hex, ephemeral_public, 32);
	uint32_t *key = map_get(dc->ephemeral_map, ephemeral_hex);
	if (!key) {
		unsigned char shared_secret[32];
		x25519_scalarmult(shared_secret, dc->rcpt_secret, ephemeral_public);
		key = malloc(32);
		sha3(shared_secret, sizeof shared_secret, key, 32);
		for (int i=0; i<8; i++) key[i] = le32toh(key[i]);
		map_set(dc->ephemeral_map, ephemeral_hex, key);
	}

	size_t len = st.st_size-40;
	fread(buf, 1, len, f);
	fclose(f);
	sha3_update(&h, buf, len);
	sha3_final(computed_hash, &h);

	chacha20_buf(buf, len, key, nonce);

	*size = len;
	return buf;
}

void *load_and_decrypt_hash(size_t *size, const unsigned char *hash, int objdir, struct decrypt_context *dc)
{
	char name[BLOBNAME_SIZE];
	gen_blob_name(name, hash);
	unsigned char computed_hash[HASHLEN];
	void *buf = load_and_decrypt_file(size, computed_hash, objdir, name, dc);
	if (buf) {
		if (memcmp(hash, computed_hash, HASHLEN)) {
			fprintf(stderr, "%s hash mismatch\n", name);
		}
	}
	return buf;
}

static struct timespec strtots(const char *s0)
{
	char *s;
	struct timespec ts;
	ts.tv_sec = strtoll(s0, &s, 10);
	ts.tv_nsec = *s=='.' ? strtol(s+1, 0, 10) : 0;
	return ts;
}

struct ctx {
	//struct crypto_context cc;
	struct decrypt_context dc;
	long long errorcnt;
	int verbose;
	int progress;
	int stop_on_errors;
	int objdir;
	int dryrun;
	struct localindex *new_index;
};

struct level {
	int fd;
	const unsigned char *data;
	size_t dlen, pos;
	const char *name;
	const unsigned char *hash;
	struct timespec mtim, ctim;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	struct level *parent, *child;
};

static int fprint_pathname(FILE *f, const struct level *lev)
{
	for (; lev->parent; lev=lev->parent);
	for (; lev; lev=lev->child)
		if (fprintf(f, "%s%s", lev->name, lev->child ? "/" : "") < 0)
			return -1;
	return 0;
}

static char *aprint_pathname(const struct level *lev)
{
	char *s;
	FILE *f = open_memstream(&s, &(size_t){0});
	if (!f) return 0;
	int err = fprint_pathname(f, lev)<0 || ferror(f);
	if (fclose(f) || err) {
		free(s);
		return 0;
	}
	return s;
}

static void error_msg(const struct level *lev, const char *op)
{
	const char *errstr = strerror(errno);
	fprint_pathname(stderr, lev);
	fprintf(stderr, ": %s: %s\n", op, errstr);
}

static int do_restore(const char *dest, const unsigned char *roothash, struct ctx *ctx)
{
	struct level *cur = calloc(1, sizeof *cur);
	struct map *hardlink_map = map_create();
	cur->name = dest;
	cur->hash = roothash;
	cur->data = load_and_decrypt_hash(&cur->dlen, roothash, ctx->objdir, &ctx->dc);
	if (!cur->data) goto fail;
	for (;;) {
		int got_blocks = 0;
		int got_idata = 0;
		unsigned long nlink = 1;
		if (!cur->pos) {
			for (;;) {
				const char *s = (const char *)cur->data+cur->pos;
				if (!memchr(cur->data+cur->pos, 0, cur->dlen-cur->pos)) {
					goto fail;
				} else if (!strncmp(s, "mode ", 5)) {
					cur->mode = strtoul(s+5, 0, 0);
				} else if (!strncmp(s, "uid ", 4)) {
					cur->uid = strtoul(s+4, 0, 0);
				} else if (!strncmp(s, "gid ", 4)) {
					cur->gid = strtoul(s+4, 0, 0);
				} else if (!strncmp(s, "mtim ", 5)) {
					cur->mtim = strtots(s+5);
				} else if (!strncmp(s, "ctim ", 5)) {
					cur->ctim = strtots(s+5);
				} else if (!strncmp(s, "nlink ", 6)) {
					nlink = strtoul(s+6, 0, 0);
				} else if (!strcmp(s, "dents")) {
					if (!S_ISDIR(cur->mode)) goto fail;
					cur->pos += 6;
					break;
				} else if (!strcmp(s, "blocks")) {
					if (S_ISDIR(cur->mode)) goto fail;
					got_blocks = 1;
					cur->pos += 7;
					break;
				} else if (!strcmp(s, "idata")) {
					if (S_ISDIR(cur->mode)) goto fail;
					got_idata = 1;
					cur->pos += 6;
					break;
				}
				cur->pos += strlen(s) + 1;
			}
			if (S_ISDIR(cur->mode) && !ctx->dryrun) {
				int pfd = cur->parent ? cur->parent->fd : AT_FDCWD;
				if (mkdirat(pfd, cur->name, 0700) && errno != EEXIST) {
					error_msg(cur, "mkdir");
					ctx->errorcnt++;
					if (ctx->stop_on_errors) goto fail;
					goto ino_done;
				}
				cur->fd = openat(pfd, cur->name, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
				if (cur->fd < 0) {
					error_msg(cur, "open");
					ctx->errorcnt++;
					if (ctx->stop_on_errors) goto fail;
					goto ino_done;
				}
			}
			if (ctx->verbose) {
				if (ctx->dryrun) {
					char hashstr[2*HASHLEN+1];
					bin2hex(hashstr, cur->hash, HASHLEN);
					fprintf(stdout, "%s ", hashstr);
				}
				fprint_pathname(stdout, cur);
				putchar('\n');
			} else if (ctx->progress) {
				printf("%s%s", cur->name, S_ISDIR(cur->mode) ? "/" : "");
				fflush(stdout);
			}
		}
		if (S_ISDIR(cur->mode) && cur->pos < cur->dlen) {
			struct level *new = calloc(1, sizeof *new);
			if (!new) goto fail;
			cur->child = new;
			new->child = 0;
			new->parent = cur;
			new->fd = -1;
			if (cur->pos+HASHLEN >= cur->dlen) goto fail;
			new->hash = cur->data+cur->pos;
			new->data = load_and_decrypt_hash(&new->dlen, new->hash, ctx->objdir, &ctx->dc);
			cur->pos += HASHLEN;
			size_t namelen = strnlen((char *)cur->data+cur->pos, cur->dlen-cur->pos);
			if (cur->data[cur->pos+namelen]) goto fail;
			new->name = (char *)cur->data + cur->pos;
			cur->pos += namelen + 1;
			if (!new->data) {
				error_msg(cur, "loading inode file");
				ctx->errorcnt++;
				if (ctx->stop_on_errors) goto fail;
				cur->child = 0;
				free(new);
				continue;
			}
			cur = new;
			continue;
		}
		if (ctx->dryrun) goto ino_done;
		if (S_ISREG(cur->mode)) {
			if (nlink > 1) {
				char hashstr[2*HASHLEN+1];
				bin2hex(hashstr, cur->hash, HASHLEN);
				char *linkto = map_get(hardlink_map, hashstr);
				if (linkto) {
					if (linkat(AT_FDCWD, linkto, cur->parent->fd, cur->name, 0)) {
						perror("link");
					}
					goto ino_done;
				}
				if (!(linkto = aprint_pathname(cur)) || map_set(hardlink_map, hashstr, linkto) < 0) {
					free(linkto);
					fprintf(stderr, "hardlinks to ");
					fprint_pathname(stderr, cur);
					fprintf(stderr, " could not be preserved\n");
				}
			}
			cur->fd = openat(cur->parent->fd, cur->name, O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
			if (cur->fd < 0) {
				error_msg(cur, "open");
				ctx->errorcnt++;
				if (ctx->stop_on_errors) goto fail;
				goto ino_done;
			}
			FILE *f = fdopen(dupe(cur->fd), "wb");
			if (!f) goto fail;
			if (got_blocks) {
				struct stat st;
				int got_stat = !fstat(cur->fd, &st);
				for (uint64_t i=0; cur->pos+HASHLEN <= cur->dlen; i++, cur->pos+=HASHLEN) {
					const unsigned char *bhash = cur->data+cur->pos;
					size_t blen;
					unsigned char *block = load_and_decrypt_hash(&blen, bhash, ctx->objdir, &ctx->dc);
					if (!block || blen < 4) break;
					fwrite(block+4, 1, blen-4, f);
					if (ctx->new_index) {
						unsigned char clearhash[HASHLEN];
						memcpy(block, "blk", 4);
						sha3(block, blen, clearhash, HASHLEN);
						localindex_setblock(ctx->new_index, clearhash, bhash);
						if (got_stat)
							localindex_setdep(ctx->new_index, st.st_dev, st.st_ino, i, clearhash);
					}
					free(block);
				}
				if (cur->pos != cur->dlen) {
					error_msg(cur, "restoring file");
					ctx->errorcnt++;
					if (ctx->stop_on_errors) goto fail;
				}
			} else if (got_idata) {
				fwrite(cur->data+cur->pos, 1, cur->dlen-cur->pos, f);
			} else {
				goto fail;
			}
			fclose(f);
		}
		if (S_ISLNK(cur->mode)) {
			char *target = strndup((char *)cur->data+cur->pos, cur->dlen-cur->pos);
			if (symlinkat(target, cur->parent->fd, cur->name)) {
				error_msg(cur, "symlink");
				ctx->errorcnt++;
				if (ctx->stop_on_errors) goto fail;
				goto ino_done;
			}
			if (fchownat(cur->parent->fd, cur->name, cur->uid, cur->gid, AT_SYMLINK_NOFOLLOW)) {
				error_msg(cur, "lchown");
			}
			if (fchmodat(cur->parent->fd, cur->name, cur->mode, AT_SYMLINK_NOFOLLOW) && errno != EOPNOTSUPP) {
				error_msg(cur, "lchmod");
			}
			if (utimensat(cur->parent->fd, cur->name, (struct timespec []){ { .tv_nsec = UTIME_OMIT }, cur->mtim }, AT_SYMLINK_NOFOLLOW)) {
				error_msg(cur, "lutimens");
			}
		} else {
			if (fchown(cur->fd, cur->uid, cur->gid)) {
				error_msg(cur, "fchown");
			}
			if (fchmod(cur->fd, cur->mode)) {
				error_msg(cur, "fchmod");
			}
			if (futimens(cur->fd, (struct timespec []){ { .tv_nsec = UTIME_OMIT }, cur->mtim })) {
				error_msg(cur, "futimens");
			}
		}
		if (ctx->new_index) {
			struct stat st;
			int r = S_ISLNK(cur->mode)
				? fstatat(cur->parent->fd, cur->name, &st, AT_SYMLINK_NOFOLLOW)
				: fstat(cur->fd, &st);
			if (!r) {
				localindex_setino(ctx->new_index, st.st_dev, st.st_ino, cur->hash);
			}
		}
ino_done:
		if (cur->fd >= 0) close(cur->fd);
		if (!ctx->verbose && ctx->progress) {
			for (size_t i=strlen(cur->name)+!!S_ISDIR(cur->mode); i>0; i--)
				fwrite("\b \b", 1, 3, stdout);
			fflush(stdout);
		}
		struct level *parent = cur->parent;
		free((void *)cur->data);
		free(cur);
		cur = parent;
		if (!cur) return ctx->errorcnt>0 ? -1 : 0;
		cur->child = 0;
	}
fail:
	printf("fail\n");
	return -1;
}



static void restore_usage(char *progname)
{
	printf("usage: %s restore -k <secret_key_file> -d <destdir> <summary_file>\n", progname);
}

int restore_main(int argc, char **argv, char *progname)
{
	int c;
	void (*usage)(char *) = restore_usage;
	const char *roothash_string = 0;
	const char *destdir = 0;
	const char *keyfile = 0;
	const char *index_file = 0;
	int dryrun = 0;
	int verbose = 0, progress = 0, stop_on_errors = 0;
	struct localindex new_index;

	while ((c=getopt(argc, argv, "r:d:k:vPSi:n")) >= 0) switch (c) {
	case 'r':
		// FIXME: not used for now
		roothash_string = optarg;
		break;
	case 'k':
		keyfile = optarg;
		break;
	case 'd':
		destdir = optarg;
		break;
	case 'v':
		verbose++;
		break;
	case 'P':
		progress = 1;
		break;
	case 'S':
		stop_on_errors = 1;
		break;
	case 'i':
		index_file = optarg;
		break;
	case 'n':
		dryrun = 1;
		verbose = 1;
		destdir = "";
		break;
	case '?':
		usage(progname);
		return 1;
	}

	if (argc-optind != 1 || !keyfile || !destdir) {
		usage(progname);
		return 1;
	}

	char *summary_file = argv[optind];
	char *final_slash = strrchr(summary_file, '/');
	int d;
	if (final_slash) {
		*final_slash = 0;
		d = open(summary_file, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
		if (!d) {
			perror("opening directory");
			return 1;
		}
		*final_slash = '/';
	} else {
		d = AT_FDCWD;
	}

	FILE *f = fopen(summary_file, "rbe");
	if (!f) {
		perror("opening summary file");
		return 1;
	}
	char buf[256];
	while (fgets(buf, sizeof buf, f)) {
		if (!strncmp(buf, "root ", 5)) roothash_string = strndup(buf+5, 2*HASHLEN);
	}
	fclose(f);

	if (!roothash_string) {
		fprintf(stderr, "no root hash found\n");
		return 1;
	}

	FILE *kf = fopen(keyfile, "rbe");
	if (!kf) {
		perror("opening key file");
		return 1;
	}
	unsigned char rcpt_secret[32];
	fread(rcpt_secret, 1, 32, kf);
	fclose(kf);

	if (index_file) {
		struct map *dev_map = map_create();
		struct stat st;
		fstat(d, &st);
		char root_dev_str[2*sizeof(dev_t)+1];
		snprintf(root_dev_str, sizeof root_dev_str, "%jx", (uintmax_t)st.st_dev);
		map_set(dev_map, root_dev_str, "");
		int new_index_fd = open(index_file, O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
		if (new_index_fd>=0) {
			if (localindex_create(&new_index, new_index_fd, dev_map) < 0)
				return 1;
		} else {
			perror("error opening new index for writing");
			return 1;
		}
	}

	struct ctx ctx = {
		.progress = progress,
		.verbose = verbose,
		.stop_on_errors = stop_on_errors,
		.objdir = d,
		.dc.rcpt_secret = rcpt_secret,
		.dc.ephemeral_map = map_create(),
		.new_index = index_file ? &new_index : 0,
		.dryrun = dryrun,
	};
	unsigned char roothash[HASHLEN];
	if (strlen(roothash_string) != 2*HASHLEN) {
		fprintf(stderr, "invalid hash %s\n", roothash_string);
		return 1;
	}
	if (!hex2bin(roothash, roothash_string, HASHLEN)) {
		fprintf(stderr, "invalid hash %s\n", roothash_string);
		return 1;
	}

	if (do_restore(destdir, roothash, &ctx)) {
		fprintf(stderr, "restore incomplete\n");
		return 1;
	}

	if (index_file) {
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		localindex_settimestamp(&new_index, &ts);
	}

	return 0;
}

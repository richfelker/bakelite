#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include "chacha20.h"
#include "x25519.h"
#include "crypto.h"
#include "sha3.h"
#include "map.h"

struct decrypt_context {
	const unsigned char *rcpt_secret;
	struct map *ephemeral_map;
};

static char *bin2hex(char *hex, const unsigned char *bin, size_t n)
{
	for (int i=0; i<n; i++)
		sprintf(hex+2*i, "%.2x", bin[i]);
	return hex;
}

static int dupe(int fd)
{
	return fcntl(fd, F_DUPFD_CLOEXEC, 0);
}

void *load_and_decrypt_file(size_t *size, unsigned char *computed_hash, const char *name, struct decrypt_context *dc)
{
	int fd = open(name, O_RDONLY|O_CLOEXEC);
	struct stat st;
	fstat(fd, &st);
	if (st.st_size > PTRDIFF_MAX) {
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

static void hashtostr(char *name, const unsigned char *hash)
{
	for (int i=0; i<HASHLEN; i++) snprintf(name+2*i, sizeof name - 2*i, "%.2x", hash[i]);
}

void *load_and_decrypt_hash(size_t *size, const unsigned char *hash, struct decrypt_context *dc)
{
	char name[2*HASHLEN+1];
	for (int i=0; i<HASHLEN; i++) snprintf(name+2*i, sizeof name - 2*i, "%.2x", hash[i]);
	unsigned char computed_hash[HASHLEN];
	void *buf = load_and_decrypt_file(size, computed_hash, name, dc);
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
	ts.tv_nsec = strtol(s, 0, 10);
	return ts;
}

struct ctx {
	//struct crypto_context cc;
	struct decrypt_context dc;
	long long errorcnt;
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

static int do_restore(const char *dest, const unsigned char *roothash, struct ctx *ctx)
{
	struct level *cur = calloc(1, sizeof *cur);
	struct map *hardlink_map = map_create();
	cur->name = dest;
	cur->data = load_and_decrypt_hash(&cur->dlen, roothash, &ctx->dc);
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
			if (S_ISDIR(cur->mode)) {
				printf("entering %s\n", cur->name);
				int pfd = cur->parent ? cur->parent->fd : AT_FDCWD;
				if (mkdirat(pfd, cur->name, 0700) && errno != EEXIST) {
					perror("mkdir");
					goto fail;
				}
				cur->fd = openat(pfd, cur->name, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
				if (cur->fd < 0) {
					perror("open");
					goto fail;
				}
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
			new->data = load_and_decrypt_hash(&new->dlen, new->hash, &ctx->dc);
			cur->pos += HASHLEN;
			size_t namelen = strnlen((char *)cur->data+cur->pos, cur->dlen-cur->pos);
			if (cur->data[cur->pos+namelen]) goto fail;
			new->name = (char *)cur->data + cur->pos;
			cur->pos += namelen + 1;
			cur = new;
			continue;
		}
		if (S_ISDIR(cur->mode)) {
			printf("leaving %s\n", cur->name);
		}
		if (S_ISREG(cur->mode)) {
			if (nlink > 1) {
				char hashstr[2*HASHLEN+1];
				hashtostr(hashstr, cur->hash);
				char *linkto = map_get(hardlink_map, hashstr);
				if (linkto) {
					if (linkat(AT_FDCWD, linkto, cur->parent->fd, cur->name, 0)) {
						perror("link");
					}
					goto ino_done;
				}
				struct level *lev;
				size_t pathlen = 0;
				FILE *f = open_memstream(&linkto, &pathlen);
				for (lev=cur; lev->parent; lev=lev->parent);
				for (; lev; lev=lev->child)
					fprintf(f, "%s%s", lev->name, lev->child ? "/" : "");
				if (ferror(f) || fclose(f)) goto fail; //fixme
				map_set(hardlink_map, hashstr, linkto);
			}
			cur->fd = openat(cur->parent->fd, cur->name, O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
			FILE *f = fdopen(dupe(cur->fd), "wb");
			if (got_blocks) {
				for (; cur->pos+HASHLEN <= cur->dlen; cur->pos+=HASHLEN) {
					size_t blen;
					unsigned char *block = load_and_decrypt_hash(&blen, cur->data+cur->pos, &ctx->dc);
					if (blen < 4) goto fail;
					fwrite(block+4, 1, blen-4, f);
					free(block);
				}
				if (cur->pos != cur->dlen) goto fail;
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
				perror("symlink");
				goto fail;
			}
			if (fchownat(cur->parent->fd, cur->name, cur->uid, cur->gid, AT_SYMLINK_NOFOLLOW)) {
				perror("lchown");
			}
			if (fchmodat(cur->parent->fd, cur->name, cur->mode, AT_SYMLINK_NOFOLLOW) && errno != EOPNOTSUPP) {
				perror("lchmod");
			}
			if (utimensat(cur->parent->fd, cur->name, (struct timespec []){ { .tv_nsec = UTIME_OMIT }, cur->mtim }, AT_SYMLINK_NOFOLLOW)) {
				perror("lutimens");
			}
		} else {
			if (fchown(cur->fd, cur->uid, cur->gid)) {
				perror("fchown");
			}
			if (fchmod(cur->fd, cur->mode)) {
				perror("fchmod");
			}
			if (futimens(cur->fd, (struct timespec []){ { .tv_nsec = UTIME_OMIT }, cur->mtim })) {
				perror("futimens");
			}
		}
ino_done:
		if (cur->fd >= 0) close(cur->fd);
		struct level *parent = cur->parent;
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
	printf("usage: %s restore -r <roothash> -k <secret_key_file> -d <destdir>\n", progname);
}

int restore_main(int argc, char **argv, char *progname)
{
	int c;
	void (*usage)(char *) = restore_usage;
	const char *roothash_string = 0;
	const char *destdir = 0;
	const char *keyfile = 0;

	while ((c=getopt(argc, argv, "r:d:k:")) >= 0) switch (c) {
	case 'r':
		roothash_string = optarg;
		break;
	case 'k':
		keyfile = optarg;
		break;
	case 'd':
		destdir = optarg;
		break;
	case '?':
		usage(progname);
		return 1;
	}

	if (argc-optind != 0) {
		usage(progname);
		return 1;
	}

	if (!keyfile || !destdir || !roothash_string) {
		usage(progname);
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

	struct ctx ctx = {
		.dc.rcpt_secret = rcpt_secret,
		.dc.ephemeral_map = map_create(),
	};
	unsigned char roothash[HASHLEN];
	if (strlen(roothash_string) != 2*HASHLEN) {
		fprintf(stderr, "invalid hash %s\n", roothash_string);
		return 1;
	}
	for (int i=0; i<HASHLEN; i++)
		if (sscanf(roothash_string+2*i, "%2hhx", roothash+i) != 1) {
			fprintf(stderr, "invalid hash %s\n", roothash_string);
			return 1;
		}

	if (do_restore(destdir, roothash, &ctx)) {
		fprintf(stderr, "restore incomplete\n");
		return 1;
	}
	return 0;
}

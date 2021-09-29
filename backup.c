#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <limits.h>
#include "sha3.h"
#include "map.h"
#include "store.h"
#include "crypto.h"
#include "bloom.h"

struct level {
	struct level *parent;
	DIR *d;
	struct dirent *de;
	int changed;
	FILE *ents;
	char *entdata;
	size_t entsize;
	struct stat st;
	const char *dev_name;
};

struct ctx {
	struct crypto_context cc;
	struct timespec since;
	const struct map *prev_index;
	struct map *new_index;
	struct map *dev_map;
	FILE *new_index_file;
	size_t bsize;
	dev_t root_dev;
	int xdev;
	long long errorcount;
	unsigned char *blockbuf;
	FILE *out;
};

FILE *ffopenat(int d, const char *name, int flags, mode_t mode)
{
	int fd = openat(d, name, flags|O_CLOEXEC, mode);
	if (fd < 0) return 0;
	const char *m;
	switch (flags&O_ACCMODE) {
	case O_RDONLY:
		m = "rb";
		break;
	case O_WRONLY:
		m = "wb";
		break;
	default:
		m = "rb+";
		break;
	}
	FILE *f = fdopen(fd, m);
	if (!f) close(fd);
	return f;
}

static struct map *index_load(FILE *f)
{
	struct map *map = map_create();
	if (!map) goto fail;

	char buf[256];
	while (fgets(buf, sizeof buf, f)) {
		int p1 = -1, p2 = -1;
		sscanf(buf, "%*s%n%*s%n", &p1, &p2);
		if (p2 < 0) goto fail;
		buf[p1] = buf[p2] = 0;
		unsigned char *val = malloc(HASHLEN);
		if (!val) goto fail;
		for (int i=0; i<HASHLEN; i++)
			sscanf(buf+p1+1+2*i, "%2hhx", &val[i]);
		if (map_set(map, buf, val) < 0) goto fail;
	}
	if (ferror(f)) goto fail;
	return map;
fail:
	if (map) map_destroy(map);
	return 0;
}

static int index_set(struct map *new_index, FILE *f, const char *hash_label, const unsigned char *blob_id)
{
	map_set(new_index, hash_label, (void *)blob_id);
	fprintf(f, "%s ", hash_label);
	for (int i=0; i<HASHLEN; i++) fprintf(f, "%.2x", blob_id[i]);
	fprintf(f, "\n");
	return 0;
}

static int emit_file_blocks(FILE *in, FILE *out, const char *ino_label, FILE *blocklist, struct ctx *ctx)
{
	const struct map *prev_index = ctx->prev_index;
	struct map *new_index = ctx->new_index;
	size_t bsize = ctx->bsize;
	struct crypto_context *cc = &ctx->cc;
	unsigned char *buf = ctx->blockbuf;

	// format of block, 0=raw is the only one defined now
	*(uint32_t *)buf = 0;
	for (long long idx=0; ; idx++) {
		size_t len = fread(buf+4, 1, bsize, in);
		if (!len) {
			int err = ferror(in);
			return err ? -1 : 0;
		}
		unsigned char *hash = malloc(HASHLEN);
		if (!hash)
			goto fail;
		sha3(buf, len, hash, HASHLEN);
		char ino_block_label[80];
		snprintf(ino_block_label, sizeof ino_block_label, "%s.%llu", ino_label, idx);
		if (index_set(new_index, ctx->new_index_file, ino_block_label, hash))
			goto fail;

		char hash_label[2*HASHLEN+1];
		for (int i=0; i<HASHLEN; i++)
			snprintf(hash_label+2*i, sizeof hash_label-2*i, "%.2x", hash[i]);
		void *blob_id = map_get(prev_index, hash_label);
		if (!blob_id) {
			blob_id = malloc(HASHLEN);
			if (!blob_id)
				goto fail;
			if (emit_new_blob(blob_id, out, buf, len+4, cc) < 0)
				goto fail;
		}
		if (!map_get(new_index, hash_label)) {
			if (index_set(new_index, ctx->new_index_file, hash_label, blob_id))
				goto fail;
		}
		if (fwrite(blob_id, 1, HASHLEN, blocklist) != HASHLEN) goto fail;
	}
fail:
	return -1;
}

static int is_later_than(const struct timespec *ts, const struct timespec *ts0)
{
	if (ts->tv_sec < ts0->tv_sec) return 0;
	if (ts->tv_sec > ts0->tv_sec || ts->tv_nsec > ts0->tv_nsec) return 1;
	return 0;
}

static int write_ino(FILE *f, struct stat *st)
{
	fprintf(f, "mode %#o%c", (unsigned)st->st_mode, 0);
	fprintf(f, "uid %u%c", (unsigned)st->st_uid, 0);
	fprintf(f, "gid %u%c", (unsigned)st->st_gid, 0);
	fprintf(f, "mtim %lld.%.9ld%c", (long long)st->st_mtim.tv_sec, st->st_mtim.tv_nsec, 0);
	fprintf(f, "ctim %lld.%.9ld%c", (long long)st->st_ctim.tv_sec, st->st_ctim.tv_nsec, 0);
	if (!S_ISDIR(st->st_mode) && st->st_nlink > 1)
		fprintf(f, "nlink %llu%c", (unsigned long long)st->st_nlink, 0);
	return 0;
}

unsigned char *walk(int base_fd, struct ctx *ctx)
{
	const struct map *prev_index = ctx->prev_index;
	struct map *new_index = ctx->new_index;
	const struct timespec *since = &ctx->since;

	struct level *cur = malloc(sizeof *cur);
	if (!cur) goto fail;

	cur->d = fdopendir(base_fd);
	if (!cur->d) goto fail;
	cur->parent = 0;
	cur->changed = 0;
	cur->ents = open_memstream(&cur->entdata, &cur->entsize);
	if (!cur->ents) goto fail;
	if (fstat(dirfd(cur->d), &cur->st)) goto fail;
	write_ino(cur->ents, &cur->st);
	fprintf(cur->ents, "dents%c", 0);

	for (;;) {
		struct stat st;
		void *data = 0;
		size_t dlen = 0;
		int changed = 0;
		int fd = -1;

		errno = 0;
		cur->de = readdir(cur->d);

		if (cur->de) {
			if (cur->de->d_name[0] == '.') {
				if (!cur->de->d_name[1]) continue;
				if (cur->de->d_name[1] == '.' && !cur->de->d_name[2]) continue;
			}

			do fd = openat(dirfd(cur->d), cur->de->d_name, O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NOCTTY);
			while (fd < 0 && errno == ELOOP && fstatat(dirfd(cur->d), cur->de->d_name, &st, AT_SYMLINK_NOFOLLOW));
			if (fd < 0 && errno != ELOOP) {
				fprintf(stderr, "error opening %s: %s\n", cur->de->d_name, strerror(errno));
				ctx->errorcount++;
				continue;
			}

			if (fd >= 0 && fstat(fd, &st)) {
				fprintf(stderr, "failed to stat %s: %s\n", cur->de->d_name, strerror(errno));
				ctx->errorcount++;
				close(fd);
				continue;
			}

			switch (st.st_mode & S_IFMT) {
			case S_IFDIR:
			case S_IFREG:
			case S_IFLNK:
			case S_IFIFO:
				break;
			default:
				fprintf(stderr, "skipping unsupported inode type %#o (%s %llx:%llu)\n",
					st.st_mode, cur->de->d_name,
					(unsigned long long)st.st_dev,
					(unsigned long long)st.st_ino);
				close(fd);
				continue;
			}

			if (st.st_dev != ctx->root_dev) {
				char dev_label[2*sizeof(uintmax_t)+1];
				snprintf(dev_label, sizeof dev_label, "%jx", (uintmax_t)st.st_dev);
				cur->dev_name = map_get(ctx->dev_map, dev_label);
				if (!cur->dev_name && !ctx->xdev)
					continue;
			}

			if (S_ISDIR(st.st_mode)) {
				struct level *new = malloc(sizeof *new);
				if (!new) goto fail;
				new->changed = 0;
				new->parent = cur;
				new->d = fdopendir(fd);
				new->st = st;
				new->ents = open_memstream(&new->entdata, &new->entsize);
				if (!new->ents) goto fail;
				write_ino(new->ents, &new->st);
				fprintf(new->ents, "dents%c", 0);
				cur = new;
				continue;
			}
		} else {
			if (errno) goto fail;
			st = cur->st;
			struct level *parent = cur->parent;
			closedir(cur->d);
			fd = -1;
			if (ferror(cur->ents)) goto fail;
			fclose(cur->ents);
			data = cur->entdata;
			dlen = cur->entsize;
			changed = cur->changed;
			free(cur);
			cur = parent;
		}

		if (is_later_than(&st.st_ctim, since) ||
		    is_later_than(&st.st_mtim, since))
			changed = 1;

		char ino_label[36];
		if (st.st_dev == ctx->root_dev)
			snprintf(ino_label, sizeof ino_label, "%ju",
				(uintmax_t)st.st_ino);
		else if (cur->dev_name)
			snprintf(ino_label, sizeof ino_label, "%s/%ju",
				cur->dev_name, (uintmax_t)st.st_ino);
		else
			snprintf(ino_label, sizeof ino_label, "%jx:%ju",
				(uintmax_t)st.st_dev, (uintmax_t)st.st_ino);

		unsigned char *ino_hash = map_get(new_index, ino_label);
		if (ino_hash)
			goto got_hardlink;
		if (!changed) {
			ino_hash = map_get(prev_index, ino_label);
			if (ino_hash) {
				char ino_block_label[80];
				for (uint64_t i=0; ; i++) {
					snprintf(ino_block_label, sizeof ino_block_label, "%s.%llu", ino_label, i);
					unsigned char *block_hash = map_get(prev_index, ino_block_label);
					if (!block_hash) break;
					if (index_set(new_index, ctx->new_index_file, ino_block_label, block_hash))
						goto fail;
					char block_hash_label[2*HASHLEN+1];
					for (int i=0; i<HASHLEN; i++)
						snprintf(block_hash_label+2*i, sizeof block_hash_label-2*i, "%.2x", block_hash[i]);
					unsigned char *enc_block_hash = map_get(prev_index, block_hash_label);
					if (index_set(new_index, ctx->new_index_file, block_hash_label, enc_block_hash))
						goto fail;
				}
				goto got_ino_hash;
			}
		}
		if (cur) cur->changed = 1;

		FILE *out = ctx->out;

		if (!S_ISDIR(st.st_mode)) {
			char *ino_data;
			size_t ino_len;
			FILE *ino_f = open_memstream(&ino_data, &ino_len);
			if (!ino_f) goto fail;
			write_ino(ino_f, &st);

			if (S_ISREG(st.st_mode)) {
				FILE *f = fdopen(fd, "rb");
				if (!f) goto fail;
				fd = -1;
				int is_small = 0;
				if (st.st_size < 4000) {
					unsigned char small_data[4000+1];
					size_t l;
					l = fread(small_data, 1, sizeof small_data, f);
					if (feof(f)) {
						fprintf(ino_f, "idata%c", 0);
						fwrite(small_data, 1, l, ino_f);
						is_small = 1;
					} else {
						rewind(f);
					}
				}
				if (!is_small) {
					fprintf(ino_f, "blocks%c", 0);
					if (emit_file_blocks(f, out, ino_label, ino_f, ctx) < 0)
						goto fail;
				}
				fclose(f);
			} else if (S_ISLNK(st.st_mode)) {
				char linkbuf[PATH_MAX];
				size_t l = readlinkat(dirfd(cur->d), cur->de->d_name, linkbuf, sizeof linkbuf);
				fprintf(ino_f, "idata%c", 0);
				fwrite(linkbuf, 1, l, ino_f);
			}

			fclose(ino_f);
			data = ino_data;
			dlen = ino_len;
		}

		// rekey for the final blob which is referenced from the signed
		// cleartext summary, so that previously used key is not linked
		// with a timestamp.
		if (!cur) cc_rekey(&ctx->cc);

		ino_hash = malloc(HASHLEN);
		if (emit_new_blob(ino_hash, out, data, dlen, &ctx->cc) < 0) goto fail;
got_ino_hash:
		if (index_set(new_index, ctx->new_index_file, ino_label, ino_hash)) goto fail;
got_hardlink:
		free(data);
		if (fd>=0) close(fd);

		if (!cur) return ino_hash;

		fwrite(ino_hash, 1, HASHLEN, cur->ents);
		fprintf(cur->ents, "%s%c", cur->de->d_name, 0);
	}
fail:
	perror("fail");
	return 0;
}

struct drop_ctx {
	FILE *f;
	const struct map *new_index;
};

static void iter_func(const char *k, const void *v, void *ctx)
{
	struct drop_ctx *dc = ctx;
	void *v2 = map_get(dc->new_index, k);
	if (v2 && !memcmp(v2, v, HASHLEN)) return;
	FILE *f = dc->f;
	fprintf(f, "drop ");
	for (int i=0; i<HASHLEN; i++) fprintf(f, "%.2x", ((unsigned char *)v)[i]);
	fprintf(f, "\n");
}

static void emit_drops(FILE *f, const struct map *prev_index, const struct map *new_index)
{
	struct drop_ctx dc = { .f = f, .new_index = new_index };
	map_iter(prev_index, iter_func, &dc);
}

static void count_iter_func(const char *k, const void *v, void *ctx)
{
	if (strchr(k, '.')) return;
	++*(long long *)ctx;
}

static void bloom_iter_func(const char *k, const void *v, void *ctx)
{
	if (strchr(k, '.')) return;
	bloom_add(ctx, v, HASHLEN);
}

static int emit_bloom(FILE *f, FILE *out, const struct map *new_index)
{
	long long count = 0;
	map_iter(new_index, count_iter_func, &count);
	struct bloom *b = bloom_create(3, count/2+1);
	map_iter(new_index, bloom_iter_func, b);
	unsigned char hash[HASHLEN];
	sha3(b->bits, b->l+32, hash, HASHLEN);
	char label[2*HASHLEN+1];
	for (int i=0; i<HASHLEN; i++) snprintf(label+2*i, 3, "%.2x", hash[i]);
	fprintf(f, "bloom %s\n", label);
	return emit_clear_file(out, label, b->bits, b->l+32);
}

static void backup_usage(char *progname)
{
	printf("usage: %s backup [options] <indexdir>\n", progname);
}

int backup_main(int argc, char **argv, char *progname)
{
	int c, d, orig_wd;
	void (*usage)(char *) = backup_usage;
	size_t bsize = 256*1024 - 128;
	int xdev = 0;
	const char *sign_with = 0, *output_to = 0;
	FILE *f, *out;
	int out_piped = 0;
	int commit_on_success = 0;
	struct stat st;
	int want_drops = 1;
	int want_bloom = 1;

	while ((c=getopt(argc, argv, "cb:xs:o:")) >= 0) switch (c) {
	case 'c':
		commit_on_success = 1;
		break;
	case 'b':
		bsize = strtoull(optarg, 0, 0);
		break;
	case 'x':
		xdev = 1;
		break;
	case 's':
		sign_with = optarg;
		break;
	case 'o':
		output_to = optarg;
		break;
	case '?':
		usage(progname);
		return 1;
	}

	if (argc-optind != 1) {
		usage(progname);
		return 1;
	}

	const char *indexdir = argv[optind];
	struct map *prev_index, *new_index, *dev_map;

	d = open(indexdir, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
	if (d < 0) {
		fprintf(stderr, "cannot open index directory %s: ", indexdir);
		perror(0);
		return 1;
	}

	orig_wd = open(".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
	if (orig_wd < 0) {
		perror("cannot open original working directory");
		return 1;
	}

	if (fchdir(d)) {
		perror("fchdir");
		return 1;
	}

	dev_map = map_create();
	if (!dev_map) {
		perror(0);
		return 1;
	}
	DIR *devdir = opendir("devices");
	if (devdir) {
		struct dirent *de;
		while (errno=0, (de = readdir(devdir))) {
			struct stat st;
			if (!fstatat(dirfd(devdir), de->d_name, &st, 0)) {
				char dev_label[2*sizeof(uintmax_t)+1];
				snprintf(dev_label, sizeof dev_label, "%jx", (uintmax_t)st.st_dev);
				char *s = strdup(de->d_name);
				if (!s || map_set(dev_map, dev_label, s)) {
					perror(0);
					return 1;
				}
			} else if (errno != ENOENT) {
				perror("stat");
				return 1;
			}
		}
		if (errno) {
			perror("readdir");
			return 1;
		}
	} else if (errno != ENOENT) {
		perror("opening devices dir");
		return 1;
	}

	if (!sign_with && !fstatat(d, "sign_cmd", &st, 0)) {
		sign_with = "./sign_cmd";
	}

	int base_fd = openat(d, "root", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
	if (base_fd < 0) {
		perror("opening directory to backup");
		return 1;
	}

	struct timespec ts0, since = { 0 };
	clock_gettime(CLOCK_REALTIME, &ts0);

	f = ffopenat(d, "index", O_RDONLY|O_CLOEXEC, 0);
	if (!f) {
		if (errno == ENOENT) {
			prev_index = map_create();
			goto no_prev_index;
		}
		perror("cannot open index file");
		return 1;
	}
	char *s=0;
	size_t n=0;
	while (getline(&s, &n, f)>=0) {
		if (!strncmp(s, "timestamp ", 10)) {
			long long t, ns;
			sscanf(s+10, "%lld.%lld", &t, &ns);
			since.tv_sec = t;
			since.tv_nsec = ns;
		} else if (!strncmp(s, "index", 5)) {
			break;
		}
	}
	prev_index = index_load(f);
	fclose(f);
no_prev_index:

	if (is_later_than(&since, &ts0)) {
		fprintf(stderr, "error: index timestamp is in the future\n");
		exit(1);
	}

	f = ffopenat(d, "index.pending", O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
	if (!f) {
		if (errno == EEXIST) {
			fprintf(stderr, "uncommitted backup already pending; commit or abort first\n");
			return 1;
		}
		perror("error opening new index for writing");
		return 1;
	}
	fprintf(f, "timestamp %lld.%.9ld\n", (long long)ts0.tv_sec, ts0.tv_nsec);
	fprintf(f, "index\n");

	new_index = map_create();
	struct ctx ctx = {
		.since = since,
		.prev_index = prev_index,
		.new_index = new_index,
		.dev_map = dev_map,
		.new_index_file = f,
		.bsize = bsize,
		.xdev = xdev,
		.blockbuf = malloc(bsize+4),
	};

	if (!ctx.blockbuf) {
		perror("malloc");
		exit(1);
	}

	FILE *kf = ffopenat(d, "pubkey", O_RDONLY|O_CLOEXEC, 0);
	if (!kf) {
		perror("error opening pubkey file");
		return 1;
	}
	if (fread(ctx.cc.rcpt_public, 1, sizeof ctx.cc.rcpt_public, kf) != sizeof ctx.cc.rcpt_public || getc(kf)!=EOF) {
		fclose(kf);
		fprintf(stderr, "invalid pubkey file\n");
		return 1;
	}
	fclose(kf);

	if (output_to) {
		if (output_to[0] == '-' && !output_to[1]) {
			out = stdout;
		} else {
			out = ffopenat(orig_wd, output_to, O_WRONLY|O_CREAT|O_EXCL, 0600);
			if (!out) {
				perror("creating output file");
			}
		}
	} else {
		out = popen("./store_cmd", "wbe");
		out_piped = 1;
		commit_on_success = 1;
	}
	ctx.out = out;
	
	fstat(base_fd, &st);
	ctx.root_dev = st.st_dev;
	unsigned char *root_hash = walk(base_fd, &ctx);
	if (!root_hash) exit(1);
	fclose(f);

	char *sumdata;
	size_t sumsize;
	f = open_memstream(&sumdata, &sumsize);
	fprintf(f, "timestamp %lld.%.9ld\n", (long long)ts0.tv_sec, ts0.tv_nsec);
	fprintf(f, "root ");
	for (int i=0; i<HASHLEN; i++) fprintf(f, "%.2x", root_hash[i]);
	fprintf(f, "\n");
	if (want_drops) {
		emit_drops(f, prev_index, new_index);
	}
	if (want_bloom) {
		emit_bloom(f, out, new_index);
	}
	fclose(f);

	struct tm tm;
	gmtime_r(&ts0.tv_sec, &tm);
	char ts_str[60], summary_name[128];
	strftime(ts_str, sizeof ts_str, "%Y-%m-%dT%H:%M:%S", &tm);
	snprintf(summary_name, sizeof summary_name - 4, "backup-%s.%.9luZ.txt", ts_str, ts0.tv_nsec);
	if (emit_clear_file(out, summary_name, sumdata, sumsize)) exit(1);

	if (sign_with) {
		strcat(summary_name, ".sig");
		emit_signature_file(out, summary_name, sumdata, sumsize, sign_with);
	}

	int r;
	if (out == stdout) r = fflush(out);
	else if (out_piped) r = pclose(out);
	else r = fclose(out);

	if (r) {
		fprintf(stderr, "error writing output\n");
		return 1;
	}
	if (commit_on_success) {
		if (renameat(d, "index.pending", d, "index")) {
			perror("rename");
			return 1;
		}
	}

	return 0;
}

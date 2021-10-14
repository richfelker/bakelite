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
#include "localindex.h"
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
	const struct localindex *prev_index;
	struct localindex *new_index;
	struct map *dev_map;
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

static int emit_file_blocks(FILE *in, FILE *out, dev_t dev, ino_t ino, FILE *blocklist, struct ctx *ctx)
{
	const struct localindex *prev_index = ctx->prev_index;
	struct localindex *new_index = ctx->new_index;
	size_t bsize = ctx->bsize;
	struct crypto_context *cc = &ctx->cc;
	unsigned char *buf = ctx->blockbuf;

	// format of block, 0=raw is the only one defined now
	for (long long idx=0; ; idx++) {
		size_t len = fread(buf+4, 1, bsize, in);
		if (!len) {
			int err = ferror(in);
			return err ? -1 : 0;
		}
		unsigned char hash[HASHLEN];
		memcpy(buf, "blk", 4);
		sha3(buf, len+4, hash, HASHLEN);
		memcpy(buf, "\0\0\0", 4);
		if (localindex_setdep(new_index, dev, ino, idx, hash) < 0)
			goto fail;

		unsigned char blob_id[HASHLEN];
		int r = localindex_getblock(prev_index, hash, blob_id);
		if (r < 0) goto fail;
		if (!r) {
			if (emit_new_blob(blob_id, out, buf, len+4, cc) < 0)
				goto fail;
		}
		r = localindex_getblock(new_index, hash, blob_id);
		if (r < 0) goto fail;
		if (!r) {
			if (localindex_setblock(new_index, hash, blob_id))
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

int walk(unsigned char *roothash, int base_fd, struct ctx *ctx)
{
	const struct localindex *prev_index = ctx->prev_index;
	struct localindex *new_index = ctx->new_index;
	const struct timespec *since = &prev_index->ts;
	int r;

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
				if (localindex_getino(new_index, st.st_dev, st.st_ino, 0) > 0) {
					fprintf(stderr, "skipping already-visited directory (%s %jx:%ju)\n",
						cur->de->d_name,
						(uintmax_t)st.st_dev,
						(uintmax_t)st.st_ino);
					close(fd);
					continue;
				}
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

		unsigned char ino_hash[HASHLEN];
		r = localindex_getino(new_index, st.st_dev, st.st_ino, ino_hash);
		if (r < 0) goto fail;
		if (r)
			goto got_hardlink;
		if (!changed) {
			r = localindex_getino(prev_index, st.st_dev, st.st_ino, ino_hash);
			if (r < 0) goto fail;
			if (r) {
				for (uint64_t i=0; ; i++) {
					unsigned char block_hash[HASHLEN], cipher_hash[HASHLEN];
					int r = localindex_getdep(prev_index, st.st_dev, st.st_ino, i, block_hash);
					if (r < 0) goto fail;
					if (!r) break;
					r = localindex_setdep(new_index, st.st_dev, st.st_ino, i, block_hash);
					r = localindex_getblock(prev_index, block_hash, cipher_hash);
					if (r <= 0) goto fail;
					if (!localindex_getblock(new_index, block_hash, 0)) {
						r = localindex_setblock(new_index, block_hash, cipher_hash);
						if (r < 0) goto fail;
					}
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
					if (emit_file_blocks(f, out, st.st_dev, st.st_ino, ino_f, ctx) < 0)
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

		if (emit_new_blob(ino_hash, out, data, dlen, &ctx->cc) < 0) goto fail;
got_ino_hash:
		if (localindex_setino(new_index, st.st_dev, st.st_ino, ino_hash) < 0)
			goto fail;
got_hardlink:
		free(data);
		if (fd>=0) close(fd);

		if (!cur) {
			memcpy(roothash, ino_hash, HASHLEN);
			return 0;
		}

		fwrite(ino_hash, 1, HASHLEN, cur->ents);
		fprintf(cur->ents, "%s%c", cur->de->d_name, 0);
	}
fail:
	perror("fail");
	return -1;
}

static int emit_bloom(FILE *f, FILE *out, const struct localindex *new_index)
{
	long long count = new_index->obj_count;
	struct bloom *b = bloom_create(3, count/2+1);
	localindex_to_bloom(new_index, b);
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
	struct map *dev_map;

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
			if (de->d_name[0] == '.') {
				if (!de->d_name[1]) continue;
				if (de->d_name[1] == '.' && !de->d_name[2]) continue;
			}
			if (strlen(de->d_name) > 16) {
				fprintf(stderr, "device name too long: %s\n", de->d_name);
				return -1;
			}
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
	fstat(base_fd, &st);
	dev_t root_dev = st.st_dev;
	char root_dev_str[2*sizeof(dev_t)+1];
	snprintf(root_dev_str, sizeof root_dev_str, "%jx", (uintmax_t)st.st_dev);
	if (!map_get(dev_map, root_dev_str) && map_set(dev_map, root_dev_str, ""))
		return 1;

	struct timespec ts0;
	clock_gettime(CLOCK_REALTIME, &ts0);

	struct localindex prev_index = { 0 }, new_index = { 0 };

	f = ffopenat(d, "index", O_RDONLY|O_CLOEXEC, 0);
	if (f) {
		if (localindex_open(&prev_index, f, dev_map) < 0)
			return 1;
		//fclose(f); // FIXME: close at right point
	} else if (errno == ENOENT) {
		if (localindex_null(&prev_index) < 0)
			return 1;
	} else {
		perror("cannot open index file");
		return 1;
	}

	if (is_later_than(&prev_index.ts, &ts0)) {
		fprintf(stderr, "error: index timestamp is in the future\n");
		exit(1);
	}

	f = ffopenat(d, "index.pending", O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
	if (f) {
		if (localindex_create(&new_index, f, &ts0, dev_map) < 0)
			return 1;
	} else {
		if (errno == EEXIST) {
			fprintf(stderr, "uncommitted backup already pending; commit or abort first\n");
			return 1;
		}
		perror("error opening new index for writing");
		return 1;
	}

	struct ctx ctx = {
		.prev_index = &prev_index,
		.new_index = &new_index,
		.root_dev = root_dev,
		.dev_map = dev_map,
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
	
	unsigned char root_hash[HASHLEN];
	if (walk(root_hash, base_fd, &ctx) < 0)
		exit(1);
	//fclose(f); // FIXME: close at right point

	char *sumdata;
	size_t sumsize;
	f = open_memstream(&sumdata, &sumsize);
	fprintf(f, "timestamp %lld.%.9ld\n", (long long)ts0.tv_sec, ts0.tv_nsec);
	fprintf(f, "root ");
	for (int i=0; i<HASHLEN; i++) fprintf(f, "%.2x", root_hash[i]);
	fprintf(f, "\n");
	if (want_bloom) {
		emit_bloom(f, out, &new_index);
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

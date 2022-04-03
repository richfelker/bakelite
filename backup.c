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
#include "binhex.h"
#include "match.h"

struct level {
	struct level *parent;
	DIR *d;
	struct dirent *de;
	int changed;
	FILE *ents;
	char *entdata;
	size_t entsize;
	struct stat st;
	int dnamelen;
};

struct ctx {
	struct crypto_context cc;
	const struct localindex *prev_index;
	struct localindex *new_index;
	struct map *dev_map;
	size_t bsize;
	dev_t root_dev;
	int xdev;
	int verbose;
	long long errorcount;
	unsigned char *blockbuf;
	FILE *out;
	FILE *verbose_f;
	struct matcher *excluder;
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

	for (long long idx=0; ; idx++) {
		size_t len = fread(buf+4, 1, bsize, in);
		if (len < bsize && !feof(in))
			goto fail;
		if (!len)
			return 0;
		unsigned char hash[HASHLEN];
		memcpy(buf, "blk", 4);
		sha3(buf, len+4, hash, HASHLEN);
		// format of block, 0=raw is the only one defined now
		memcpy(buf, "\0\0\0", 4);
		if (localindex_setdep(new_index, dev, ino, idx, hash) < 0)
			goto fail;

		unsigned char blob_id[HASHLEN];
 		int r = localindex_getblock(new_index, hash, blob_id);
		if (r < 0) goto fail;
		if (!r) {
			r = localindex_getblock(prev_index, hash, blob_id);
			if (r < 0) goto fail;
			if (!r) {
				if (emit_new_blob(blob_id, out, buf, len+4, cc) < 0)
					goto fail;
			}
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
	char *pathbuf;
	size_t pathbuf_size;
	FILE *path_f = open_memstream(&pathbuf, &pathbuf_size);
	if (putc('/', path_f)<0) goto fail;

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
		char linkbuf[PATH_MAX];
		ssize_t linklen = 0;

		errno = 0;
		cur->de = readdir(cur->d);

		if (cur->de) {
			if (cur->de->d_name[0] == '.') {
				if (!cur->de->d_name[1]) continue;
				if (cur->de->d_name[1] == '.' && !cur->de->d_name[2]) continue;
			}

			do fd = openat(dirfd(cur->d), cur->de->d_name, O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
			while (fd < 0 && errno == ELOOP && fstatat(dirfd(cur->d), cur->de->d_name, &st, AT_SYMLINK_NOFOLLOW));
			if (fd < 0 && errno != ELOOP) {
				// silently ignore unix sockets (& bad device nodes)
				if (errno == ENXIO) continue;
				fprintf(stderr, "error opening %s: %s\n", cur->de->d_name, strerror(errno));
				ctx->errorcount++;
				continue;
			}
			if (fd >= 0) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);

			if (fd >= 0 && fstat(fd, &st)) {
				fprintf(stderr, "failed to stat %s: %s\n", cur->de->d_name, strerror(errno));
				ctx->errorcount++;
				close(fd);
				continue;
			}

			switch (st.st_mode & S_IFMT) {
			case S_IFLNK:
				linklen = readlinkat(dirfd(cur->d), cur->de->d_name, linkbuf, sizeof linkbuf);
				if (linklen < 0) {
					fprintf(stderr, "failed to read symlink %s: %s\n", cur->de->d_name, strerror(errno));
					ctx->errorcount++;
					close(fd);
					continue;
				}
				break;
			case S_IFDIR:
			case S_IFREG:
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
				if (!map_get(ctx->dev_map, dev_label) && !ctx->xdev) {
					close(fd);
					continue;
				}
			}

			int namelen = fprintf(path_f, "%s%s%c", cur->de->d_name,
				S_ISDIR(st.st_mode) ? "/" : "", 0) - 1;
			if (namelen < 0 || fflush(path_f) ||
			    fseeko(path_f, -1, SEEK_CUR) < 0)
				goto fail;
			if (matcher_matches(ctx->excluder, pathbuf)) {
				if (fseeko(path_f, -namelen, SEEK_CUR) < 0)
					goto fail;
				r = localindex_getino(prev_index, st.st_dev, st.st_ino, 0);
				if (r < 0) goto fail;
				if (r) cur->changed = 1;
				close(fd);
//				fprintf(ctx->verbose_f, "EXCLUDING %s\n", pathbuf);
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
				if (!new->d) goto fail;
				new->st = st;
				new->ents = open_memstream(&new->entdata, &new->entsize);
				new->dnamelen = namelen;
				if (!new->ents) goto fail;
				write_ino(new->ents, &new->st);
				fprintf(new->ents, "dents%c", 0);
				cur = new;
				continue;
			} else {
				if (fseeko(path_f, -namelen, SEEK_CUR)<0)
					goto fail;
			}
		} else {
			if (errno) goto fail;
			st = cur->st;
			struct level *parent = cur->parent;
			closedir(cur->d);
			fd = -1;
			if (fflush(cur->ents) || ferror(cur->ents))
				goto fail;
			fclose(cur->ents);
			data = cur->entdata;
			dlen = cur->entsize;
			changed = cur->changed;
			if (fputc(0, path_f)<0 || fflush(path_f) ||
			    fseeko(path_f, -cur->dnamelen-1, SEEK_CUR)<0)
				goto fail;
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
					if (r < 0) goto fail;
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
				fprintf(ino_f, "idata%c", 0);
				fwrite(linkbuf, 1, linklen, ino_f);
			}

			if (fflush(ino_f) || ferror(ino_f))
				goto fail;
			fclose(ino_f);
			data = ino_data;
			dlen = ino_len;
		}

		if (ctx->verbose) fprintf(ctx->verbose_f, "%s\n", pathbuf);

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
	bin2hex(label, hash, HASHLEN);
	fprintf(f, "bloom %s\n", label);
	char name[BLOBNAME_SIZE];
	gen_blob_name(name, hash);
	return emit_clear_file(out, name, b->bits, b->l+32);
}

static void backup_usage(char *progname)
{
	printf("usage: %s backup [options]\n", progname);
}

int backup_main(int argc, char **argv, char *progname)
{
	int c, d;
	void (*usage)(char *) = backup_usage;
	size_t bsize = 256*1024;
	int xdev = 0;
	int verbose = 0;
	const char *sign_with = 0, *output_to = 0;
	FILE *f, *out;
	int out_piped = 0;
	int commit_on_success = 0;
	int dry_run = 0;
	struct stat st;
	int want_bloom = 1;
	char bak_label[64] = "backup";

	while ((c=getopt(argc, argv, "cb:xs:o:nv")) >= 0) switch (c) {
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
	case 'n':
		dry_run = 1;
		break;
	case 'v':
		verbose = 1;
		break;
	case '?':
		usage(progname);
		return 1;
	}

	if (argc-optind != 0) {
		usage(progname);
		return 1;
	}

	struct map *dev_map;

	d = open(".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
	if (d < 0) {
		perror("cannot open working directory");
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

	int prev_index_fd = openat(d, "index", O_RDONLY|O_CLOEXEC);
	if (prev_index_fd>=0) {
		if (localindex_open(&prev_index, prev_index_fd, dev_map) < 0)
			return 1;
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

	f = ffopenat(d, "config", O_RDONLY|O_CLOEXEC, 0);
	if (f) {
		char buf[256];
		while (fgets(buf, sizeof buf, f)) {
			size_t l = strlen(buf);
			if (l && buf[l-1]=='\n') buf[--l] = 0;
			if (!strncmp(buf, "label ", 6)) {
				snprintf(bak_label, sizeof bak_label, "%s", buf+6);
			} else if (!strncmp(buf, "blocksize ", 10)) {
				bsize = strtoul(buf+10, 0, 0);
			}
		}
	} else if (errno != ENOENT) {
		perror("opening config file");
		return 1;
	}

	f = ffopenat(d, "exclude", O_RDONLY|O_CLOEXEC, 0);
	struct matcher *excluder = 0;
	if (f) {
		excluder = matcher_from_file(f);
		if (!excluder) {
			perror("loading exclusions");
			return 1;
		}
		fclose(f);
	} else if (errno != ENOENT) {
		perror("opening exclude file");
		return 1;
	}

	if (bsize < 4000) {
		fprintf(stderr, "block size %zu too small\n", bsize);
		return 1;
	} else if (bsize > 64<<20) {
		fprintf(stderr, "block size %zu too large\n", bsize);
		return 1;
	}
	bsize -= 48; // covers cryptographic and data internal headers

	int new_index_fd = openat(d, "index.pending", O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
	if (new_index_fd>=0) {
		if (localindex_create(&new_index, new_index_fd, dev_map) < 0)
			return 1;
		if (localindex_settimestamp(&new_index, &ts0) < 0)
			return 1;
	} else {
		if (errno == EEXIST) {
			fprintf(stderr, "uncommitted backup already pending; commit or abort first\n");
			return 1;
		}
		perror("error opening new index for writing");
		return 1;
	}
	if (dry_run) {
		unlinkat(d, "index.pending", 0);
		commit_on_success = 0;
	}

	struct ctx ctx = {
		.prev_index = &prev_index,
		.new_index = &new_index,
		.root_dev = root_dev,
		.dev_map = dev_map,
		.bsize = bsize,
		.xdev = xdev,
		.verbose = verbose,
		.verbose_f = stdout,
		.blockbuf = malloc(bsize+4),
		.excluder = excluder,
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

	if (dry_run) {
		out = ffopenat(d, "/dev/null", O_WRONLY, 0);
		if (!out) {
			perror("opening /dev/null");
			return 1;
		}
	} else if (output_to) {
		if (output_to[0] == '-' && !output_to[1]) {
			out = stdout;
		} else {
			out = ffopenat(d, output_to, O_WRONLY|O_CREAT|O_EXCL, 0600);
			if (!out) {
				perror("creating output file");
				return 1;
			}
		}
	} else {
		out = popen("./store_cmd", "w");
		if (!out) {
			perror("opening pipe to store_cmd");
			return 1;
		}
		out_piped = 1;
		commit_on_success = 1;
	}
	ctx.out = out;
	
	unsigned char root_hash[HASHLEN];
	if (walk(root_hash, base_fd, &ctx) < 0)
		exit(1);
	localindex_close(&prev_index);
	close(prev_index_fd);

	char *sumdata;
	size_t sumsize;
	f = open_memstream(&sumdata, &sumsize);
	fprintf(f, "timestamp %lld.%.9ld\n", (long long)ts0.tv_sec, ts0.tv_nsec);
	fprintf(f, "label %s\n", bak_label);
	fprintf(f, "root ");
	for (int i=0; i<HASHLEN; i++) fprintf(f, "%.2x", root_hash[i]);
	fprintf(f, "\n");
	if (want_bloom) {
		emit_bloom(f, out, &new_index);
	}
	fclose(f);
	localindex_close(&new_index);
	close(new_index_fd);

	struct tm tm;
	gmtime_r(&ts0.tv_sec, &tm);
	char ts_str[60], summary_name[128];
	strftime(ts_str, sizeof ts_str, "%Y-%m-%dT%H%M%S", &tm);
	snprintf(summary_name, sizeof summary_name - 4, "%s-%s.%.9luZ.txt", bak_label, ts_str, ts0.tv_nsec);
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

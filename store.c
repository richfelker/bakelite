#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "sha3.h"
#include "crypto.h"
#include "chacha20.h"

int emit_file_record(FILE *f, const char *name, size_t len)
{
	struct tar_header {
		char name[100];
		char mode[8], uid[8], gid[8], size[12], mtime[12], cksum[8], type, linked[100];
		char magic[6], ver[2];
		char user[32], group[32];
		char major[8], minor[8];
		char prefix[155];
		char pad[12];
		//char pad[512-257];
	} h = {
		.mode = "0000644", .uid = "0000000", .gid = "0000000", .mtime = "0000000",
		.cksum = "        ", .type = '0',
		.magic = "ustar", .ver = "00",
	};
	snprintf(h.name, sizeof h.name, "%s", name);
	snprintf(h.size, sizeof h.size, "%.7zo", len); // FIXME - check that it fits
	int sum = 0;
	for (int i=0; i<sizeof h; i++)
		sum += ((unsigned char *)&h)[i];
	snprintf(h.cksum, sizeof h.cksum, "%.6zo", sum);
	fwrite(&h, 1, sizeof h, f);
	return 0;
}

static int emit_pad(size_t unpadded_size, FILE *f)
{
	static const char zeros[511];
	size_t cnt = -unpadded_size & 511;
	if (fwrite(zeros, 1, cnt, f) != cnt) return -1;
	return 0;
}

int emit_new_blob(unsigned char *label, FILE *f, unsigned char *data, size_t len, struct crypto_context *cc)
{
	uint64_t nonce = get_nonce(cc);
	chacha20_buf(data, len, cc->ephemeral_key, nonce);

	sha3_ctx_t h;
	sha3_init(&h, HASHLEN);
	sha3_update(&h, cc->ephemeral_public, sizeof cc->ephemeral_public);
	nonce = htole64(nonce);
	sha3_update(&h, &nonce, sizeof nonce);
	sha3_update(&h, data, len);
	char label_hex[2*HASHLEN+1];
	sha3_final(label, &h);
	for (int i=0; i<HASHLEN; i++)
		snprintf(label_hex+2*i, 3, "%.2x", label[i]);

	size_t blob_size = len + sizeof cc->ephemeral_public + sizeof nonce;
	emit_file_record(f, label_hex, blob_size);
	fwrite(cc->ephemeral_public, 1, sizeof cc->ephemeral_public, f);
	fwrite(&(uint64_t){htole64(nonce)}, 1, sizeof nonce, f);
	fwrite(data, 1, len, f);
	emit_pad(blob_size, f);
	return 0;
}

int emit_clear_file(FILE *f, const char *name, const void *data, size_t len)
{
	if (emit_file_record(f, name, len) ||
	    fwrite(data, 1, len, f) != len ||
	    emit_pad(len, f))
		return -1;
	return 0;
}

int emit_signature_file(FILE *out, const char *name, const void *data, size_t dlen, const char *signing_cmd)
{
	pid_t pid = -1;
	extern char **environ;
	int pout[2]={-1,-1}, pin[2]={-1,-1};
	posix_spawn_file_actions_t fa;
	int fa_live = 0;
	int ret = -1;
	FILE *f = 0;
	char *sigdata = 0;
	size_t sigsize = 0;
	ssize_t siglen;

	if (pipe2(pout, O_CLOEXEC) || pipe2(pin, O_CLOEXEC))
		goto fail;
	if (posix_spawn_file_actions_init(&fa))
		goto fail;
	fa_live = 1;

	if (posix_spawn_file_actions_adddup2(&fa, pout[0], 0) ||
	    posix_spawn_file_actions_adddup2(&fa, pin[1], 1) ||
	    posix_spawn_file_actions_addclose(&fa, pout[1]) ||
	    posix_spawn_file_actions_addclose(&fa, pin[0]) ||
	    posix_spawnp(&pid, "sh", &fa, 0, (char *[])
	                 { "sh", "-c", (char *)signing_cmd, 0 },
	                 environ))
	{
		goto fail;
	}
	close(pout[0]); pout[0] = -1;
	close(pin[1]); pin[1] = -1;
	f = fdopen(pout[1], "wb");
	if (!f) goto fail;
	pout[1] = -1;

	if (fwrite(data, 1, dlen, f) != dlen || fflush(f))
		goto fail;
	fclose(f); f = 0;
	
	f = fdopen(pin[0], "rb");
	if (!f) goto fail;
	pin[0] = -1;

	siglen = getdelim(&sigdata, &sigsize, 0, f);
	if (siglen < 0) goto fail;
	fclose(f); f = 0;

	if (emit_file_record(out, name, siglen)) goto fail;
	if (fwrite(sigdata, 1, siglen, out) != siglen) goto fail;
	if (emit_pad(siglen, out) || fflush(out)) goto fail;

fail:
	if (fa_live) posix_spawn_file_actions_destroy(&fa);
	if (pout[0]>=0) close(pout[0]);
	if (pout[1]>=0) close(pout[1]);
	if (pin[0]>=0) close(pin[0]);
	if (pin[1]>=0) close(pin[1]);
	int status = 0;
	if (pid>=1) waitpid(pid, &status, 0);
	if (status) ret = -1;
	free(sigdata);
	return ret;
}

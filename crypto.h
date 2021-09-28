#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

#define HASHLEN 28

struct crypto_context {
	unsigned char ephemeral_public[32];
	unsigned char rcpt_public[32];
	uint32_t ephemeral_key[8];
	uint64_t seq;
};

uint64_t get_nonce(struct crypto_context *);

#define cc_rekey(cc) ((cc)->seq = 0)

#endif

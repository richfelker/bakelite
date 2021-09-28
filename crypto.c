#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include "crypto.h"
#include "x25519.h"
#include "sha3.h"

uint64_t get_nonce(struct crypto_context *cc)
{
	if (!cc->seq) {
		unsigned char ephemeral_secret[32];
		if (getentropy(ephemeral_secret, 32)) abort();
		x25519_scalarmult(cc->ephemeral_public, ephemeral_secret, (unsigned char [32]){9});
		// x25519_scalarmult is assumed to allow input and output to alias.
		// using that property helps clean key from memory slightly.
		x25519_scalarmult(ephemeral_secret, ephemeral_secret, cc->rcpt_public);
		sha3(ephemeral_secret, sizeof ephemeral_secret, cc->ephemeral_key, sizeof cc->ephemeral_key);
		for (int i=0; i<8; i++)
			cc->ephemeral_key[i] = le32toh(cc->ephemeral_key[i]);
		cc->seq = 1;
	}
	// in host byte order already; might need change if we use different nonce
	return cc->seq++;
}

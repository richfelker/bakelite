#ifndef STORE_H
#define STORE_H

#include "crypto.h"

int emit_file_record(FILE *, const char *, size_t);
int emit_new_blob(unsigned char *, FILE *, unsigned char *, size_t, struct crypto_context *);
int emit_clear_file(FILE *, const char *, const void *, size_t);
int emit_signature_file(FILE *, const char *, const void *, size_t, const char *);
void gen_blob_name(char *name, const unsigned char *hash);

#define BLOBNAME_PREFIX "objects/XXX/"
#define BLOBNAME_SIZE (2*HASHLEN + sizeof BLOBNAME_PREFIX)

#endif

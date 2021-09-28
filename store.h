#ifndef STORE_H
#define STORE_H

struct crypto_context;
int emit_file_record(FILE *, const char *, size_t);
int emit_new_blob(unsigned char *, FILE *, unsigned char *, size_t, struct crypto_context *);
int emit_clear_file(FILE *, const char *, const void *, size_t);
int emit_signature_file(FILE *, const char *, const void *, size_t, const char *);

#endif

#ifndef CHACHA20_H
#define CHACHA20_H

void chacha20_block(uint32_t *, const uint32_t *, uint64_t, uint64_t);
void chacha20_buf(unsigned char *, size_t, const uint32_t *, uint64_t);

#endif

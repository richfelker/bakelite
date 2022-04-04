#ifndef __BAKELITE_COMPATS_ENDIAN_H
# if defined(HAVE_ENDIAN_H)
#  include <endian.h>
# elif defined(HAVE_SYS_ENDIAN_H)
#  include <sys/endian.h>
#  if defined(HAVE_ENDIAN_NONSTANDARD_TOH)
#	define be16toh(x) betoh16(x)
#	define le16toh(x) letoh16(x)
#	define be32toh(x) betoh32(x)
#	define le32toh(x) letoh32(x)
#	define be64toh(x) betoh64(x)
#	define le64toh(x) letoh64(x)
#  endif
# elif defined(HAVE_OSBYTEORDER_H)
#  include <libkern/OSByteOrder.h>
#  define htobe16(x) OSSwapHostToBigInt16(x)
#  define htole16(x) OSSwapHostToLittleInt16(x)
#  define be16toh(x) OSSwapBigToHostInt16(x)
#  define le16toh(x) OSSwapLittleToHostInt16(x)
#  define htobe32(x) OSSwapHostToBigInt32(x)
#  define htole32(x) OSSwapHostToLittleInt32(x)
#  define be32toh(x) OSSwapBigToHostInt32(x)
#  define le32toh(x) OSSwapLittleToHostInt32(x)
#  define htobe64(x) OSSwapHostToBigInt64(x)
#  define htole64(x) OSSwapHostToLittleInt64(x)
#  define be64toh(x) OSSwapBigToHostInt64(x)
#  define le64toh(x) OSSwapLittleToHostInt64(x)
# else
#  include <stdint.h>
#  if defined(IS_ENDIAN_BIG)
#   define htobe16(x) (uint16_t)(x)
#   define htole16(x) (uint16_t)(((uint8_t)(x&0xff)<<8)|(uint8_t)((x&0xff00)>>8))
#   define htobe32(x) (uint32_t)(x)
#   define htole32(x) (uint32_t)((htole16(x&0xffff)<<16)|(htole16((x&0xffff0000)>>16)))
#   define htobe64(x) (uint64_t)(x)
#   define htole64(x) (uint64_t)((htole32(x&0xffffffff)<<32)|(htole16((x&0xffffffff00000000)>>32)))
#   define le16toh(x) (uint16_t)(((uint8_t)(x&0xff)<<8)|(uint8_t)((x&0xff00)>>8))
#   define be16toh(x) (uint16_t)(x)
#   define le32toh(x) (uint32_t)((le16toh(x&0xffff)<<16)|(le16toh((x&0xffff0000)>>16)))
#   define be32toh(x) (uint32_t)(x)
#   define le64toh(x) (uint32_t)((le32toh(x&0xffffffff)<<32)|(le32toh((x&0xffffffff00000000)>>32)))
#   define be64toh(x) (uint64_t)(x)
#  elif defined(IS_ENDIAN_LITTLE)
#   define htole16(x) (uint16_t)(x)
#   define htobe16(x) (uint16_t)(((uint8_t)(x&0xff)<<8)|(uint8_t)((x&0xff00)>>8))
#   define htole32(x) (uint32_t)(x)
#   define htobe32(x) (uint32_t)((htobe16(x&0xffff)<<16)|(htobe16((x&0xffff0000)>>16)))
#   define htole64(x) (uint64_t)(x)
#   define htobe64(x) (uint64_t)((htobe32(x&0xffffffff)<<32)|(htobe16((x&0xffffffff00000000)>>32)))
#   define be16toh(x) (uint16_t)(((uint8_t)(x&0xff)<<8)|(uint8_t)((x&0xff00)>>8))
#   define le16toh(x) (uint16_t)(x)
#   define be32toh(x) (uint32_t)((be16toh(x&0xffff)<<16)|(le16toh((x&0xffff0000)>>16)))
#   define le32toh(x) (uint32_t)(x)
#   define be64toh(x) (uint32_t)((be32toh(x&0xffffffff)<<32)|(le32toh((x&0xffffffff00000000)>>32)))
#   define le64toh(x) (uint64_t)(x)
#  endif
# endif
# define __BAKELITE_COMPATS_ENDIAN_H
#endif
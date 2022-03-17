// linux types from `vmlinux.h`

#ifndef __LINUX_TYPES_H
#define __LINUX_TYPES_H

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

#ifndef __aligned_u64
# define __aligned_u64 __u64 __attribute__((aligned(8)))
#endif

#endif /* __LINUX_TYPES_H */

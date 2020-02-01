/*
 * GOST R 34.11-2012 core functions definitions.
 *
 * Copyright (c) 2013 Cryptocom LTD.
 * This file is distributed under the same license as OpenSSL.
 *
 * Author: Alexey Degtyarev <alexey@renatasystems.org>
 *
 */

#include "cpu.h"
#include <string.h>

#ifdef IS_X86
# define UNALIGNED_MEM_ACCESS
/*Assume other platforms not capable read unaligned memory
  or this operations are not fast enough 
*/ 
#endif

#if defined(IS_X86_64)
/* x86-64 bit Linux and Windows ABIs provide malloc function that returns 16-byte alignment
  memory buffers required by SSE load/store instructions. Other platforms require special trick  
  for proper gost2012_hash_ctx structure allocation. It will be easier to switch to unaligned 
  loadu/storeu memory access instructions in this case.
*/  
# define GOST_ALIGNED_MEMORY
#endif

#ifdef FORCE_UNALIGNED_MEM_ACCESS  
# undef GOST_ALIGNED_MEMORY
# undef UNALIGNED_MEM_ACCESS
#endif

#ifndef L_ENDIAN
# define __GOST3411_BIG_ENDIAN__
#endif

#if defined(_WIN32) || defined(_WINDOWS)
# define INLINE __inline
# define UNALIGNED __unaligned 
#else
# define INLINE inline
# define UNALIGNED 
#endif

#ifdef _MSC_VER
# define GOST_ALIGN(x) __declspec(align(x))
#else
# define GOST_ALIGN(x) __attribute__ ((__aligned__(x)))
#endif

#if defined(__GNUC__) || defined(__clang__)
# define RESTRICT __restrict__
#else
# ifdef _MSC_VER
#   define RESTRICT  __restrict
# else  
#   define RESTRICT
# endif
#endif

GOST_ALIGN(16)
typedef union uint512_u {
    unsigned long long QWORD[8];
    unsigned char B[64];
} uint512_t;

/* GOST R 34.11-2012 hash context */
typedef struct gost2012_hash_ctx {
    union uint512_u buffer;
    union uint512_u h;
    union uint512_u N;
    union uint512_u Sigma;
    size_t bufsize;
    unsigned int digest_size;
} gost2012_hash_ctx;

#include "gosthash2012_const.h"
#include "gosthash2012_precalc.h"

void init_gost2012_hash_ctx(gost2012_hash_ctx * CTX,
                            const unsigned int digest_size);
void gost2012_hash_block(gost2012_hash_ctx * CTX,
                         const unsigned char *data, size_t len);
void gost2012_finish_hash(gost2012_hash_ctx * CTX, unsigned char *digest);

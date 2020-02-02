/*
 * GOST R 34.11-2012 core functions definitions.
 *
 * Copyright (c) 2013 Cryptocom LTD.
 * This file is distributed under the same license as OpenSSL.
 *
 * Author: Alexey Degtyarev <alexey@renatasystems.org>
 *
 */

#include <string.h>

#if !defined(__x86_64__) && defined(_M_X64) 
# define __x86_64__
#endif

#if !defined(__i386__) && defined(_M_IX86)
# define __i386__
#endif

#ifdef OPENSSL_IA32_SSE2
# if defined(__SSE2__) || defined(_M_X64) 
#  define __GOST3411_HAS_SSE2__
# endif
#endif

#ifdef __x86_64__
# define UNALIGNED_MEM_ACCESS
/* x86-64 bit Linux and Windows ABIs provide malloc function that returns 16-byte alignment
  memory buffers required by SSE load/store instructions. Other platforms require special trick  
  for proper gost2012_hash_ctx structure allocation. It will be easier to switch to unaligned 
  loadu/storeu memory access instructions in this case.
*/  
# define GOST_ALIGNED_MEMORY
#else
#ifdef __i386__
# define UNALIGNED_MEM_ACCESS
#endif
/*Assume other platforms not capable read/write unaligned memory
  or this operations are not fast enough 
*/ 
#endif

#ifdef __GOST3411_HAS_SSE2__
# if defined(__GNUC__) && ((__GNUC__ < 4) || (__GNUC__ == 4 && __GNUC_MINOR__ < 2))
#  undef __GOST3411_HAS_SSE2__
# endif
#endif

#ifdef FORCE_UNALIGNED_MEM_ACCESS  
# undef GOST_ALIGNED_MEMORY
# undef UNALIGNED_MEM_ACCESS
#endif

#ifndef L_ENDIAN
# define __GOST3411_BIG_ENDIAN__
#endif

#if defined __GOST3411_HAS_SSE2__
# include "gosthash2012_sse2.h"
#else
# include "gosthash2012_ref.h"
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
} uint512_u;

#include "gosthash2012_const.h"
#include "gosthash2012_precalc.h"

/* GOST R 34.11-2012 hash context */
typedef struct gost2012_hash_ctx {
    union uint512_u buffer;
    union uint512_u h;
    union uint512_u N;
    union uint512_u Sigma;
    size_t bufsize;
    unsigned int digest_size;
} gost2012_hash_ctx;

void init_gost2012_hash_ctx(gost2012_hash_ctx * CTX,
                            const unsigned int digest_size);
void gost2012_hash_block(gost2012_hash_ctx * CTX,
                         const unsigned char *data, size_t len);
void gost2012_finish_hash(gost2012_hash_ctx * CTX, unsigned char *digest);

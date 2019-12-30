/*
 * GOST R 34.11-2012 core functions.
 *
 * Copyright (c) 2013 Cryptocom LTD.
 * This file is distributed under the same license as OpenSSL.
 *
 * Author: Alexey Degtyarev <alexey@renatasystems.org>
 *
 */

#include "gosthash2012.h"
#include <assert.h>

#ifdef __x86_64__

# include <immintrin.h>
# ifdef __clang__
# elif __GNUC__
#  include <x86intrin.h>
# else
#  include <intrin.h>
# endif
#endif

#define BSWAP64(x) \
    (((x & 0xFF00000000000000ULL) >> 56) | \
     ((x & 0x00FF000000000000ULL) >> 40) | \
     ((x & 0x0000FF0000000000ULL) >> 24) | \
     ((x & 0x000000FF00000000ULL) >>  8) | \
     ((x & 0x00000000FF000000ULL) <<  8) | \
     ((x & 0x0000000000FF0000ULL) << 24) | \
     ((x & 0x000000000000FF00ULL) << 40) | \
     ((x & 0x00000000000000FFULL) << 56))

/*
 * Initialize gost2012 hash context structure
 */
void init_gost2012_hash_ctx(gost2012_hash_ctx * CTX,
                            const unsigned int digest_size)
{
    memset(CTX, 0, sizeof(gost2012_hash_ctx));

    CTX->digest_size = digest_size;
    if (digest_size == 256)
        memset(&CTX->h, 0x01, sizeof(uint512_u));
}

static INLINE void pad(gost2012_hash_ctx * CTX)
{    
    assert( CTX->bufsize < 64 );
    
    memset(&(CTX->buffer.B[CTX->bufsize]), 0x00, sizeof(CTX->buffer) - CTX->bufsize  );
    CTX->buffer.B[CTX->bufsize] = 0x01;
}

static INLINE void add512(union uint512_u * RESTRICT x, const union uint512_u * UNALIGNED RESTRICT y)
{
    
#ifdef __x86_64__
    unsigned char CF=0;
    unsigned int i;
    
    for (i = 0; i < 8; i++)
    {
        CF = _addcarry_u64(CF, x->QWORD[i] , y->QWORD[i], &(x->QWORD[i]) );     
    }
    
#elif __GOST3411_BIG_ENDIAN__
    const unsigned char *yp;
    unsigned char *xp;
    unsigned int i;
    int buf;

    xp = (unsigned char *)&x[0];
    yp = (const unsigned char *)&y[0];
    

    buf = 0;
    for (i = 0; i < 64; i++) {
        buf = xp[i] + yp[i] + (buf >> 8);
        xp[i] = (unsigned char)buf & 0xFF;
    }
#else
    unsigned long CF=0;
    unsigned long long tmp;
    unsigned int i;

    for (i = 0; i < 8; i++)
    {
        tmp = x->QWORD[i] + y->QWORD[i] + CF;
    
        if (tmp != x->QWORD[i])
            CF = (tmp < x->QWORD[i]);
        
        x->QWORD[i] = tmp;        
    }
#endif
}

static void g(union uint512_u * RESTRICT h, const union uint512_u * RESTRICT N,
              const union uint512_u * UNALIGNED RESTRICT m)
{
#ifdef __GOST3411_HAS_SSE2__
    __m128i xmm0, xmm2, xmm4, xmm6; /* XMMR0-quadruple */
    __m128i xmm1, xmm3, xmm5, xmm7; /* XMMR1-quadruple */
    unsigned int i;

    LOAD(N, xmm0, xmm2, xmm4, xmm6);
    XLPS128M(h, xmm0, xmm2, xmm4, xmm6);
    ULOAD(m, xmm1, xmm3, xmm5, xmm7);

    XLPS128R(xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7);

    for (i = 0; i < 11; i++)
        ROUND128(i, xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7);

    XLPS128M((&C[11]), xmm0, xmm2, xmm4, xmm6);
    X128R(xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7);

    X128M(h, xmm0, xmm2, xmm4, xmm6);
    ULOAD(m, xmm1, xmm3, xmm5, xmm7);
    X128R(xmm0, xmm2, xmm4, xmm6, xmm1, xmm3, xmm5, xmm7);

    STORE(h, xmm0, xmm2, xmm4, xmm6);
#if 0
    /* Restore the Floating-point status on the CPU. Require only for MMX version */
    _mm_empty();
#endif    
#else
    union uint512_u Ki, data;
    unsigned int i;

    XLPS(h, N, (&data));

    /* Starting E() */
    Ki = data;
    XLPS((&Ki), ((const union uint512_u *)&m[0]), (&data));

    for (i = 0; i < 11; i++)
        ROUND(i, (&Ki), (&data));

    XLPS((&Ki), (&C[11]), (&Ki));
    X((&Ki), (&data), (&data));
    /* E() done */

    X((&data), h, (&data));
    X((&data), m, h);
#endif
}

static INLINE void stage2(gost2012_hash_ctx * CTX, const union uint512_u * UNALIGNED data)
{
    g(&(CTX->h), &(CTX->N), data );

    add512(&(CTX->N), &buffer512);
    add512(&(CTX->Sigma), data );
}

static INLINE void stage3(gost2012_hash_ctx * CTX)
{
    pad(CTX);

    g(&(CTX->h), &(CTX->N), &(CTX->buffer) );

    add512(&(CTX->Sigma), &(CTX->buffer));

    memset(&(CTX->buffer.B[0]), 0x00, sizeof(uint512_u) );  
#ifndef __GOST3411_BIG_ENDIAN__
    CTX->buffer.QWORD[0] = CTX->bufsize << 3;
#else
    CTX->buffer.QWORD[0] = BSWAP64(CTX->bufsize << 3);
#endif
       
    add512(&(CTX->N), &(CTX->buffer));
    g(&(CTX->h), &buffer0, &(CTX->N));
    g(&(CTX->h), &buffer0, &(CTX->Sigma));
}

/*
 * Hash block of arbitrary length
 *
 */
void gost2012_hash_block(gost2012_hash_ctx * CTX,
                         const unsigned char * data, size_t len)
{
    register size_t chunksize;
    register size_t bufsize = CTX->bufsize;
    
    if(bufsize==0){
        while(len>=64){
#ifdef UNALIGNED_MEM_ACCESS
            stage2(CTX, (const union uint512_u *)data );
#else
            memcpy(&CTX->buffer.B[0], data, 64);
                stage2(CTX, &(CTX->buffer) );
#endif
            len   -= 64;
            data  += 64;            
        }
    }   
        
    while (len) {
        chunksize = 64 - bufsize;
        if (chunksize > len)
            chunksize = len;

        memcpy(&(CTX->buffer.B[bufsize]), data, chunksize);

        bufsize += chunksize;
        len     -= chunksize;
        data    += chunksize;

        if (bufsize == 64) {
            stage2(CTX, &(CTX->buffer) );
            bufsize = 0;
        }
    }
    CTX->bufsize = bufsize;
}

/*
 * Compute hash value from current state of ctx
 * state of hash ctx becomes invalid and cannot be used for further
 * hashing.
 */
void gost2012_finish_hash(gost2012_hash_ctx * CTX, unsigned char *digest)
{
    stage3(CTX);

    CTX->bufsize = 0;

    if (CTX->digest_size == 256)
        memcpy(digest, &(CTX->h.QWORD[4]), 32);
    else
        memcpy(digest, &(CTX->h.QWORD[0]), 64);
}

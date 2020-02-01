#include "cpu.h"
#ifdef IS_X86
#include "gosthash2012.h"
#include "gosthash2012_sse2.h"

void g_sse2(union uint512_u * RESTRICT h, const union uint512_u * RESTRICT N,
              const union uint512_u * UNALIGNED RESTRICT m)
{
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
}
#endif

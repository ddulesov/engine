#include "gosthash2012.h"
#include "gosthash2012_ref.h"

void g_ref(union uint512_u * RESTRICT h, const union uint512_u * RESTRICT N,
              const union uint512_u * UNALIGNED RESTRICT m)
{
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
}

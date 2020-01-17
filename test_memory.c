/*
 * Test GOST memory
*/

#include "e_gost_err.h"
#include "gost_lcl.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <string.h>
#include <stdlib.h>
#if MIPSEL
# include <sys/sysmips.h>
#endif

static void hexdump(const void *ptr, size_t len)
{
    const unsigned char *p = ptr;
    size_t i, j;

    for (i = 0; i < len; i += j) {
	for (j = 0; j < 16 && i + j < len; j++)
	    printf("%s%02x", j? "" : " ", p[i + j]);
    }
    printf("\n");
}


#define T(e) ({ if (!(e)) { \
		ERR_print_errors_fp(stderr); \
		OpenSSLDie(__FILE__, __LINE__, #e); \
	    } \
        })
#define TE(e) ({ if (!(e)) { \
		ERR_print_errors_fp(stderr); \
		fprintf(stderr, "Error at %s:%d %s\n", __FILE__, __LINE__, #e); \
		return -1; \
	    } \
        })

#define cRED	"\033[1;31m"
#define cDRED	"\033[0;31m"
#define cGREEN	"\033[1;32m"
#define cDGREEN	"\033[0;32m"
#define cBLUE	"\033[1;34m"
#define cDBLUE	"\033[0;34m"
#define cNORM	"\033[m"
#define TEST_ASSERT(e) {if ((test = (e))) \
		 printf(cRED "  Test FAILED\n" cNORM); \
	     else \
		 printf(cGREEN "  Test passed\n" cNORM);}


static int do_test()
{
	void *buf;
	for(int i=0;i<2 * 1024;i++){
		buf = OPENSSL_malloc(i<<1);
		if( 0x0f &  (size_t)buf ){
			printf(cRED "unaligned address found %p \n", buf );
			return 1;
		}
		OPENSSL_free(buf);
	} 
	for(int i=0;i<2 * 1024;i++){
		buf = malloc(i<<1);
		if( 0x0f &  (size_t)buf ){
			printf(cRED "unaligned address found %p \n", buf );
			return 1;
		}
		free(buf);
	} 		
		
	
	return 0;
}

int main(int argc, char **argv)
{
    int ret = 0;
#ifndef __x86_64__
    printf(cGREEN "test skipped\n", cNORM );
    return 0;
#endif

#if MIPSEL
    /* Trigger SIGBUS for unaligned access. */
    sysmips(MIPS_FIXADE, 0);
#endif
    setenv("OPENSSL_ENGINES", ENGINE_DIR, 0);
    OPENSSL_add_all_algorithms_conf();
    ERR_load_crypto_strings();
    ENGINE *eng;
    T(eng = ENGINE_by_id("gost"));
    T(ENGINE_init(eng));
    T(ENGINE_set_default(eng, ENGINE_METHOD_ALL));

    do_test();

    ENGINE_finish(eng);
    ENGINE_free(eng);

    if (ret)
	printf(cDRED "= Some tests FAILED!\n" cNORM);
    else
	printf(cDGREEN "= All tests passed!\n" cNORM);
    return ret;
}

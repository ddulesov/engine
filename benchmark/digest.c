/**********************************************************************
 *             Simple benchmarking for gost-engine                    *
 *                                                                    *
 *       This file is distributed under the same license as OpenSSL   *
 **********************************************************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../test.h"
#include "../ansi_terminal.h"
#include "platform.h"
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>

#ifdef _MSC_VER
#include "../getopt.h"
#else
#include <getopt.h>
#endif

#include "../gosthash2012.h"

static unsigned char * create_buffer(size_t size)
{
    unsigned char * ptr = malloc(size);
    size_t i;
    T(ptr);
    
    for(i=0;i<size;i++){
        ptr[i] =  i & 0xFF;
    }
    return ptr;
}

static inline void free_buffer(unsigned char* ptr){
    free(ptr);
}

static void usage(char *name)
{
    fprintf(stderr, "usage: %s [-c cycles] [-s samples] [-b digest_size]"
    "\n\tcycles      - accaptable value >=10000"
    "\n\tsamples     - 5(default). acceptable value: 1 - 1000"
    "\n\tdigest_size - 256 (default) or 512\n", name);
    exit(1);
}

const unsigned int MIN_CYCLES = 10000;
const size_t bs[]={32, 64, 256, 1024, 1024*8, 9732, 1024*64 };
#define  bs_count  sizeof(bs)/sizeof(bs[0])
#define EVP_MAX_MD_SIZE  64

const char * M1 = "012345678901234567890123456789012345678901234567890123456789012";
const size_t M1_SIZE = 63;
const char * M1_DIGEST  =
	"\x9d\x15\x1e\xef\xd8\x59\x0b\x89"
	"\xda\xa6\xba\x6c\xb7\x4a\xf9\x27"
	"\x5d\xd0\x51\x02\x6b\xb1\x49\xa4"
	"\x52\xfd\x84\xe5\xe5\x7b\x55\x00";
	

const char* SEP1= "\n--------";

int main(int argc, char **argv)
{
    unsigned int i, j, c;
    unsigned int cycles = MIN_CYCLES;
    unsigned int samples = 5;
    const char * name = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];

    int nid;
    int option;
    int digest_size = 512;
    const EVP_MD * evp_md;
    double perf[bs_count];
    
    opterr = 0;
    while((option = getopt(argc, argv, "b:s:c:")) >= 0)
    {
        if(option == ':') option = optopt;
        if(optarg && (optarg[0] == '-')) { optind--; optarg = NULL; }
        switch (option)
        {
            case 'c':
                cycles = atoi(optarg);
                break;
            case 'b':
                digest_size = atoi(optarg);
                break;
            case 's':
                samples = atoi(optarg);
                break;
            default:
                usage(argv[0]);
                break;
        }
    }
    if (optind < argc) usage(argv[0]);
    if (cycles < MIN_CYCLES) { puts("cycles too small. the value should be 10000 or more"); exit(1); }
    if (samples == 0 ) { puts("samples value must be greater than 0"); exit(1); }
    
    switch(digest_size){
        case 256:
            nid = NID_id_GostR3411_2012_256;
            name = "GOST-R 34.11-2012(256)";
            break;
        case 512:
            nid = NID_id_GostR3411_2012_512;
            name = "GOST-R 34.11-2012(512)";
            break;
        default:
            puts("only 256 and 512 bit digest supported"); 
            exit(1);

    }

    OPENSSL_add_all_algorithms_conf();
    ERR_load_crypto_strings();
    setupConsole();
    /* test GOST engine is OK */
    evp_md = EVP_get_digestbynid(NID_id_GostR3411_2012_256);
    if(!EVP_Digest(M1, M1_SIZE, md, NULL, evp_md, NULL) || memcmp(md, M1_DIGEST, 32 ) ){
        printf(cRED "'%s' returns error. Ensure GOST engine is configured properly\n",name);
        restoreConsole();
        exit(1);
    }

    evp_md = EVP_get_digestbynid(nid);
    printf(" %s. block size / digest speed, MBps\n", name);
    
    printf("#/size%*s",2,"");  
    for(i=0; i< bs_count; i++){
        printf("%10zi", bs[i]); 
    }
    
    printf("%s",SEP1);
    for(i=0; i< bs_count * 10; i++){
        printf("-");
    }
          
    for(j=0; j<samples; j++){
        printf("\nstep %i/%i...", j+1, samples );
        fflush(stdout);
        
        for(i=0; i< bs_count; i++){
            TIMER_INIT;            
            unsigned char * buf;
            
            buf = create_buffer( bs[i] );
            TIMER_START;
            for(c=0; c<cycles; c++){
                EVP_Digest(buf, bs[i], md, NULL, evp_md, NULL);   
            }
            TIMER_STOP;
            free_buffer( buf );
          
            perf[i] = (double)(cycles * bs[i])/ elapsedTime;
        }
        
        printf("\r%8i", j+1);
        for(i=0; i< bs_count; i++){
            printf("%10.2f", perf[i] );
        }
    }
    
    printf("%s",SEP1);
    for(i=0; i< bs_count * 10; i++){
        printf("-");
    }
    puts(cGREEN"\n Completed");
    restoreConsole();
    exit(0);
}

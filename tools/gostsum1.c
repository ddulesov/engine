/***
 Copyright (c) 2020, Dmitry Dulesov  <dmitry.dulesov@gmail.com>

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
***/
#ifdef _AIO
#define _GNU_SOURCE
#endif
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <stdatomic.h>
#include <stdbool.h>

#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>

#include "../gosthash2012.h"

#ifdef _AIO
#include <sys/syscall.h>    /* for __NR_* definitions */
#include <libaio.h>

///async IO syscall wrapper functions
int 
io_setup(int nr, io_context_t *ctxp){
    return syscall(__NR_io_setup, nr, ctxp);
}

int 
io_destroy(io_context_t ctx){
    return syscall(__NR_io_destroy, ctx);
}

int 
io_submit(io_context_t ctx, long nr,  struct iocb **iocbpp) {
    return syscall(__NR_io_submit, ctx, nr, iocbpp);
}

int 
io_getevents(io_context_t ctx, long min_nr, long max_nr,
        struct io_event *events, struct timespec *timeout){
    return syscall(__NR_io_getevents, ctx, min_nr, max_nr, events, timeout);
}
#endif

static _Bool flag_noasync    = false;
static _Bool flag_verbose    = false;
static _Bool flag_longhash   = false;
static _Bool flag_stdin      = false;
static _Bool flag_statistics = false;

#define handle_error_en(en, msg) \
       do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define handle_error(msg) \
       do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define test_error( f, msg ) \
        do{ s = f; if(s!=0){ errno=s; perror(msg); exit(EXIT_FAILURE); } } while (0)
               
#define RES_INIT    0x0000
#define RES_SUBM    0x0001
#define RES_TAKE    0x0002

#define RES_COMP_MASK  0xFF00

#define RES_HEQU    0xFF00
#define RES_HDIFF   0xFF01
#define RES_EFILE   0xFF02

#define IS_RESULT_OK(task_res)     (task_res == RES_HEQU)
#define IS_RESULT_ERR(task_res)    (task_res != RES_HEQU)

#define DEF_FNAME_LEN       256

#define FILE_READ_BUF_SIZE  (1024 * 8)
#define THREAD_STACK_SIZE   (1024 * 16)
#define MIN_CHECK_FILE_SIZE  4000

#define TASK_RES_OK     0
#define TASK_RES_ASYNC  1

#define S_OK            0
#define S_ERR_HASH      1
#define S_ERR_FORMAT    2
#define S_ERR_MEM       3
#define S_ERR           4

#define TASK_QUEUE_SIZE     10  /* 4 .. 126 */

#define TWEAK_TASK_MAIN_LOOP 0 /*0 ..  */
#define TWEAK_TASK_DISP     4  /*0 .. TASK_QUEUE_SIZE */
#define TWEAK_TASK_RELEASE  1  /*0 .. TWEAK_TASK_DISP */
#define TWEAK_TASK_FREE     2  /*0 .. TWEAK_TASK_DISP */

///simple and fast hex to bin conversion 
inline static  unsigned int 
_hex2bin(int c) {
    c -= 48;
    c = (c>48)?(c-32): c;
    return (c>16)?c-7: c;
}

///digest hex representation
inline static void
hex2out(const unsigned char* buff, size_t len){
    for (int i = 0; i < len; i++) {
        printf("%02x", buff[i]);
    }
}

///pthread local storage 
struct thread_info {    
    pthread_t thread_id;   /* thread ID returned by pthread_create() */
};

struct task {
    _Alignas(64) gost2012_hash_ctx   ctx;
    unsigned char       digest[64];
    unsigned int      digest_size;
    atomic_uint       result;
    //filename buffer
    char*               filename;
    size_t              fcapacity;
};

typedef struct task  task_t;
typedef unsigned int result_t;

static void 
task_init(task_t* task){
    atomic_store_explicit(&task->result, RES_INIT, memory_order_relaxed );
    task->fcapacity = 0;
    task->filename = NULL;  
}

static void
task_free(task_t* task){
    if(task->filename!=NULL && task->fcapacity>0){
        free((void*)task->filename);
        task_init(task);
    }
}

inline static result_t
task_get_result(task_t* task){
    return atomic_load_explicit(&(task->result), memory_order_acquire);
}

inline static void
task_release(task_t* task){
    /* !RES_INIT not using in syncronization so can use relaxed memory order */
    atomic_store_explicit(&(task->result), RES_INIT, memory_order_relaxed ); 
}

///Output file digest check status 
static void
task_print_status(const task_t* task, result_t res ){
    if(task==NULL || task->filename==NULL){
        return;
    }
    printf("%s - %s\n", task->filename, ( res==RES_HEQU )?"OK":"ERROR" );
}

static _Bool 
task_hex2digest(task_t* task, int shift, const char *str){
    unsigned int c;
    const char* pend = str+64;
    while(str<pend){
        c  = _hex2bin(*str++) << 4;
        c += _hex2bin(*str++);
        if(c>0xFF){
            return false;
        }
        task->digest[shift++] = c;
    }
    return true;
}
///Compare actual and calculated digests
inline static _Bool
task_cmpdigest(const task_t* task, unsigned const char* actual){
    return memcmp(task->digest, actual, task->digest_size)==0;
}

///digest calculation routine based on libc file API 
static int
task_getdigest_libc(task_t* task, unsigned char* digest){
    
    unsigned char buff[ FILE_READ_BUF_SIZE ];
    size_t bytes;
    int res = S_OK;
    FILE *f;
    
    if(task==NULL)
        return S_ERR;
    
    if(task->filename==NULL && task->fcapacity==0){
        f = stdin;
    }else{
        f = fopen(task->filename,"rb");
        if(f == NULL)
            return S_ERR;
#if 0       
        /* Can improve file cache usage */
        posix_fadvise(fileno(f), 0, 0, POSIX_FADV_SEQUENTIAL);
#endif
    }

    init_gost2012_hash_ctx(&task->ctx, (int) task->digest_size  * 8 );
    
    while ((bytes = fread(buff, 1, FILE_READ_BUF_SIZE, f)) > 0) {
        gost2012_hash_block(&task->ctx, buff, bytes );
    }
    
    if (ferror(f)) {
        res = S_ERR;
        goto err;   
    }
    
    gost2012_finish_hash(&task->ctx, digest);
err:
    if(f!=NULL && f!=stdin)
        fclose(f);
    return res;
}

#ifdef _AIO

///digest calculation routine based on Linux AIO API
static int
task_getdigest_aio(task_t* task, unsigned char* digest){
    
    size_t sh;
    long long offset;
    size_t  len;
    int res = S_OK;
    unsigned char *buff;
    struct iocb cb = {0};
    struct io_event events[1];
    struct iocb* iocbs = &cb;
    io_context_t ctx = {0};
    int fd;

    if(task==NULL)
        return S_ERR;
    
    if(task->filename==NULL && task->fcapacity==0){
        return task_getdigest_libc(task, digest);
    }
    
    if(io_setup(1, &ctx) < 0) {
        handle_error("io_setup");
    }
    
    fd = open(task->filename, O_RDONLY | O_DIRECT );  
    if(fd==-1){
        return S_ERR;
    }
    
    if(posix_memalign((void **)&buff, 512, FILE_READ_BUF_SIZE * 2)!=0)
        goto err;
    
    res = S_ERR;
    offset = 0;
    io_prep_pread(&cb, fd, buff, FILE_READ_BUF_SIZE, offset);
    if(io_submit(ctx, 1, &iocbs) < 1 ){
        goto err;
    }
        
    sh = 0;
    init_gost2012_hash_ctx(&task->ctx, (int) task->digest_size  * 8 );
    
    do{
        if(io_getevents(ctx, 1, 1, events, NULL)!=1){
            goto err;
        }
        printf("event %ld %ld \n", events[0].res, events[0].res2);
        len = events[0].res2;
        
        if(len > 0){
            unsigned char*  ptr = buff + sh;
            //start new request
            offset += len;
            
            sh = (sh + FILE_READ_BUF_SIZE) % (2 * FILE_READ_BUF_SIZE);
            io_prep_pread(&cb, fd, buff+sh, FILE_READ_BUF_SIZE, offset);
            if(io_submit(ctx, 1, &iocbs) < 1 ){
                goto err;
            }
            
            gost2012_hash_block(&task->ctx, ptr, len ); 
        }   
    }while(len>0);          
    
    gost2012_finish_hash(&task->ctx, digest);
    res = S_OK;
err:
    
    io_destroy(ctx);
    free(buff);
    close(fd);
    
    return res;
}

    static int task_getdigest(task_t* task, unsigned char* digest) __attribute__ ((alias ("task_getdigest_aio"))) ; 
#else
    static int task_getdigest(task_t* task, unsigned char* digest) __attribute__ ((alias ("task_getdigest_libc"))) ;  
#endif

inline static result_t
task_validate(task_t* task){
    unsigned char actual[64]; 
    int s = task_getdigest(task, actual);
    if(s != S_OK){
        return RES_EFILE;
    };
    
    return task_cmpdigest(task, actual)? RES_HEQU: RES_HDIFF;
}

struct master_context {
    //task slots
    task_t     tasks[ TASK_QUEUE_SIZE ];
    unsigned int            stop;
    pthread_mutex_t         mutex;
    //master wait for free task slot
    pthread_cond_t          cv_master;
    //workers wait for new tasks
    pthread_cond_t          cv_worker;  
    atomic_uint           await;
};
typedef struct master_context master_context_t;

static void
master_context_init(master_context_t *mi){
    int s;
    mi->stop=0;
    
    for(int i=0;i<TASK_QUEUE_SIZE; i++){
        task_init( &(mi->tasks[i]) );
    };
    
    atomic_store_explicit(&(mi->await), 0, memory_order_release );
    test_error( pthread_mutex_init(&mi->mutex,NULL), "pthread_mutex_init" );
    test_error( pthread_cond_init(&mi->cv_master, NULL), "pthread_cond_init" );// = PTHREAD_COND_INITIALIZER;
    test_error( pthread_cond_init(&mi->cv_worker, NULL), "pthread_cond_init");// = PTHREAD_COND_INITIALIZER;
}

static void
master_context_free(master_context_t *mi){
    for(int i=0;i<TASK_QUEUE_SIZE; i++){
        task_free( &(mi->tasks[i]) );
    }
    pthread_cond_destroy(&(mi->cv_master));
    pthread_cond_destroy(&(mi->cv_worker));
    pthread_mutex_destroy(&(mi->mutex));
}

inline static void
master_context_stop(master_context_t *mi){
    /* We can set stop status without mutex syncronization. I'm not sure. */
    //pthread_mutex_lock(&mi->mutex);
    mi->stop = 1;
    pthread_cond_broadcast(&mi->cv_worker);
    //pthread_mutex_unlock(&mi->mutex);
}
 
inline static _Bool
master_context_has_complete(master_context_t *mi){
    result_t task_result;
    
    for(int i=0; i<TASK_QUEUE_SIZE; i++ ){
        task_result = task_get_result( &(mi->tasks[i]) );
        if(RES_COMP_MASK & task_result){
            return true;
        }
    }
    return false;
} 
///Wait for accomplished task 
static void 
master_context_master_wait(master_context_t *mi){
    pthread_mutex_lock(&mi->mutex);
    if(!master_context_has_complete(mi) )
        pthread_cond_wait(&mi->cv_master, &mi->mutex);
    
    pthread_mutex_unlock(&mi->mutex);
} 

///Wait for submitted task
static unsigned int 
master_context_worker_wait(master_context_t *mi){
    pthread_mutex_lock(&mi->mutex);
    unsigned int await;
    while((await = atomic_load_explicit(&mi->await, memory_order_consume))==0 && mi->stop==0  )
        pthread_cond_wait(&mi->cv_worker, &mi->mutex);
    
    pthread_mutex_unlock(&mi->mutex);
    return await;
} 
///Notify worker thread about new task 
static void 
master_context_signal_master(master_context_t *mi){
    pthread_mutex_lock(&mi->mutex);
    atomic_fetch_add_explicit(&(mi->await), 1, memory_order_release ); 
    pthread_cond_signal(&mi->cv_worker);
    pthread_mutex_unlock(&mi->mutex);
}
 
///Worker thread function
static void *
thread_start(void *arg)
{
    master_context_t *mi = arg;

    long done = 0;
    //the number of submitted task that are not taken by worker threads
    unsigned int await = 0;
    result_t task_result;
    
    do{
        //look for a submitted task
        for(int i=0;await>0 && i<TASK_QUEUE_SIZE; i++ ){
            task_t *ptask = &(mi->tasks[i]);
            task_result = task_get_result( ptask );
            
            if(RES_SUBM == task_result 
                && atomic_compare_exchange_weak_explicit(&(ptask->result),
                &task_result, 
                RES_TAKE,
                memory_order_release, memory_order_relaxed)  
                ){
                //notify other worker we take the task
                atomic_fetch_sub_explicit(&(mi->await), 1, memory_order_release ); 
                //do work
                task_result = task_validate(ptask);
                //notify the master process that we are ready 
                pthread_mutex_lock(&mi->mutex);
                done++;
                atomic_store_explicit(&ptask->result, task_result, memory_order_release );
                
                pthread_cond_signal(&mi->cv_master);
                pthread_mutex_unlock(&mi->mutex);
                
                /*another strategies are 
                  - break loop
                  - continue loop; 
                */
                i=0; //reset loop and try catch new task
                await = atomic_load_explicit(&mi->await, memory_order_consume);
            }
        }  
        //put worker thread in sleep if no any submitted task 
        await = master_context_worker_wait(mi);
    }while(mi->stop==0 && await>0 );
    
    return (void*)done;
}
///Submit new digest verify task or execute it inplace if the async parameter is NULL
inline static int
submit_task(task_t *task, master_context_t* async){
    if(async==NULL){
        atomic_store_explicit(&task->result, task_validate(task) , memory_order_release );
        return TASK_RES_OK; // sync call 
    }
    //async call
    atomic_store_explicit(&task->result, RES_SUBM , memory_order_release );
    
    //signal master task ready 
    master_context_signal_master(async);
    return TASK_RES_ASYNC;
}
///Read trailing line as filename
inline static int
read_filename(task_t *ptask, FILE* f){
    size_t r, r1, r2;
    size_t sh = 0;
    //allocate default size buffer if none was allocated before
    if(ptask->filename==NULL /* || ptask->fcapacity==0 */){
        //default capacity
        ptask->filename = malloc(DEF_FNAME_LEN);
        
        if(ptask->filename == NULL){
            return S_ERR_MEM;
        }
        ptask->fcapacity = DEF_FNAME_LEN;
        r = DEF_FNAME_LEN;
    }else{
        r = ptask->fcapacity;
    }
    /* read line up to line-break. If buffer space is not enough to store all data
    allocate more memory. Buffer space is increased by DEF_FNAME_LEN bytes but not more than  PATH_MAX  */
    do{
        //
        r1 = ftell(f); 
        char* ptr = fgets(ptask->filename+sh, r, f);
        if(ptr==NULL){
            return S_ERR_FORMAT;
        };
        r2 = ftell(f); 
        if(r2<=r1){
            return S_ERR_FORMAT;
        }
        sh += r2 - r1; //read bytes count
        
        ptr+= (r2 - r1 -1);
        if( *ptr!='\n' ){
            //check file buffer size exceed max file name length
            if(ptask->fcapacity >= PATH_MAX)
                return S_ERR_FORMAT; //too long filename
            //increase buffer size
            r = DEF_FNAME_LEN;
            ptr = realloc(ptask->filename, ptask->fcapacity + r);
            if(ptr == NULL)
                return S_ERR_MEM;
            ptask->filename =  ptr;
            ptask->fcapacity+= r;
            
        }else{
            //trim new line and line break symbols at the end of line
            *ptr-- = '\0';
            if( *ptr=='\r' ){
                *ptr = '\0';
            }
            return S_OK;
        }
        
    }while(ferror(f)==0);
    
    return S_ERR_MEM;
}
///Process digest check file command
static int 
check(const char* filename){
    master_context_t mi;
    master_context_t* async_context = &mi;
    
    struct thread_info *tinfo=NULL;
    pthread_attr_t attr;
    result_t  task_result;

    char buff[64];
    int s;
    int res = S_OK;
    size_t r;
    FILE *f;
    int num_threads=2;
    unsigned long ln;
    
    f= fopen(filename, "r");
    if(f==NULL){
        return S_ERR; 
    }
    //get file size
    fseek(f , 0 , SEEK_END);                          
    r = ftell(f); 
    fseek(f , 0 , SEEK_SET); 
    if(r< MIN_CHECK_FILE_SIZE || flag_noasync){
        async_context = NULL;
    }
    
    if(async_context){
        master_context_init(&mi);
        
        s = pthread_attr_init(&attr);
        test_error( pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE), "pthread_attr_setstacksize" );
        
        //some heuristics to figure out optimum number of worker threads
        num_threads = get_nprocs();
        if(num_threads<=0){
            num_threads = 2;
        }else if(num_threads>6){
            num_threads=6;
        }
    
        tinfo = calloc(num_threads, sizeof(struct thread_info));
        if (tinfo == NULL)
            handle_error("calloc");
        
        //create  thread pool
        for (int tnum = 0; tnum < num_threads; tnum++) {
           test_error( pthread_create(&tinfo[tnum].thread_id, &attr,
                              &thread_start, &mi), "pthread_create" );
        }
        test_error( pthread_attr_destroy(&attr), "pthread_attr_destroy" );
    }
    //check file line number
    ln = 1;
    //system call status code
    s =  0;
    /*just initialized tasks queue has only free blocks.
    Take last block for instance */
    task_t*  ptask = &(mi.tasks[TASK_QUEUE_SIZE-1]);
    do{
        r = fread(buff, 1, sizeof(buff), f);
        if(r!=sizeof(buff) ){
            if(r>0)res = S_ERR_FORMAT; else ln = 0;
            break;
        }
        
        //find first free slot.
        //make it in lock free loop
        s = TWEAK_TASK_MAIN_LOOP;
        while(ptask==NULL){
            int cc= TWEAK_TASK_DISP; //tweak parameter
            for(int i=0; cc>=0 && i<TASK_QUEUE_SIZE; i++ ){
                task_t*  pt = &(mi.tasks[i]);
                task_result = task_get_result( pt );
                switch(task_result){
                    case RES_HDIFF:
                    case RES_EFILE:
                        //trigger error status on both file io error and digest mismatch
                        res =S_ERR_HASH;
                    case RES_HEQU:
                        if(flag_verbose){
                            task_print_status(pt, task_result);
                        }
                        task_release(pt);
                        cc-= TWEAK_TASK_RELEASE; // number of release 
                        ptask = pt;
                        break;
                    case RES_INIT:
                        ptask = pt;
                        cc-=TWEAK_TASK_FREE; // number of free slots
                        break;
                    default:
                        break;
                }
            }
            s--;
            //If no one found push thread to waitable state
            if(ptask==NULL){
                if(s<=0){
                    master_context_master_wait(&mi);
                }else{
                    sched_yield();
                }
            }
        }
        
        assert(ptask!=NULL);
        //Convert digest hex representation to binary value
        if(!task_hex2digest(ptask, 0, buff)){
            res = S_ERR_FORMAT; 
            break;
        }
        char c = fgetc(f);
        if(c!=' '){
            //probably long hash format
            r = fread(&buff[1], 1, sizeof(buff)-1, f);
            if(r!=sizeof(buff)-1 ){
                res = S_ERR_FORMAT; 
                break;
            }
            buff[0]=c;
            if(!task_hex2digest(ptask, 32, buff)){
                res = S_ERR_FORMAT; 
                break;
            }
            //hash digest and file name must be separated by one space
            if(fgetc(f)!=' '){
                res = S_ERR_FORMAT; 
                break;
            };
            //long 512 bit hash used
            ptask->digest_size = 64;
        }else{
            //reqular 256 bit hash used
            ptask->digest_size = 32;
        }

        s = read_filename(ptask, f);
        if( s!=S_OK ){
            res = s;
            break;
        }
            
        /*run task performing hash calculation and compare it with expected value.
        Depends on last parameter it can be sent to a worker thread (async)
        or to this  thread (sync) */
        s = submit_task(ptask, async_context);
        if(s == TASK_RES_OK){ //sync task
            task_result = task_get_result(ptask);
            if(flag_verbose){
                task_print_status(ptask, task_result);
            }
            if(IS_RESULT_ERR(task_result))
                res = S_ERR_HASH;
            //task_release(ptask);
        }else{ // async task 
            ptask = NULL; //force find new free slot
        };
        
        ln++;
    }while( !feof(f) );
    
    fclose(f);
    
    if(async_context){
        //send stop signal
        master_context_stop(&mi);
        //join threads
        for (int tnum = 0; tnum < num_threads; tnum++) {
            void* done;
            test_error( pthread_join(tinfo[tnum].thread_id, &done), "pthread_join" );
        }
        //free memory          
        free(tinfo);
        //print last accomplished tasks
        for(int i=0; i<TASK_QUEUE_SIZE; i++ ){
            task_t*  pt = &(mi.tasks[i]);
            task_result = task_get_result( pt );
            
            switch(task_result){
                case RES_HDIFF:
                case RES_EFILE:
                    res = S_ERR_HASH;
                case RES_HEQU:
                    if(flag_verbose){
                        task_print_status(pt, task_result);
                    }
                    //task_release(pt);
                    break;
                default:
                    break;
            }       
        }
        master_context_free(&mi);
    }
    
    if(flag_verbose && ln>0 && res==S_ERR_FORMAT){
        printf("improperly formated line %ld\n",ln);
    }
    return res;
}

static int  
printusage(const char* executable){
    fputs( "Calculates GOST R 34.11-2012 hash function\n\n", stderr);
    fprintf(stderr, "%s [-hvl][-c checkfile|filename|-]\n", executable);	
	fputs("\t-c check message digests (default is generate)\n"
            "\t-v verbose, print file names when checking\n"
            "\t-l use 512 bit hash (default 256 bit)\n"
            "\t-h print this help\n"
			"\t - use stdin to calculate hash\n"
            "The input for -c should be the list of message digests and file names\n"
            "that is printed on stdout by this program when it generates digests.", stderr);
			
    return 1;
}

int 
main (int argc, char *argv[]){
    int res = 0;
    const char* check_filename=NULL;

    while ( (res = getopt(argc,argv,"nhxlvVc:") ) != -1){
        switch (res){    
            case 'n': flag_noasync=true; break;
            case 'v': flag_verbose=true; break;
            case 'V': flag_statistics=true; break;
            case 'l': flag_longhash=true; break;
            case 'x': flag_stdin=true; break;
            case 'c': check_filename = optarg; break;
            case '?': 
            case 'h': return printusage(argv[0]); break;
            default: 
                fprintf(stderr, "invalid option %c\n", optopt);
                printusage(argv[0]);
        };
    };
    
    if(check_filename){
        return check(check_filename);
    }else if (argv[optind] !=NULL  || flag_stdin){
        unsigned char actual[64];
        
        task_t  t;
        task_init(&t);
        
        if( strcmp(argv[optind], "-") ==0 ){
            flag_stdin = true;
        }else{
            t.filename = argv[optind];
        }
        
        t.digest_size = flag_longhash?64:32;
        res = task_getdigest_libc(&t, actual);    
        task_free(&t);
        if(res==S_OK){
            hex2out(actual,t.digest_size );
            if(flag_verbose){
                printf(" %s\n",argv[optind]);
            }else{
                puts("");
            }
        }
        return res;

    }else{
        return printusage(argv[0]);
    }
    
    return res;
}
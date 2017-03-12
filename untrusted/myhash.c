#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include "murmur3_hash.h"
//#include "jenkins_hash.h"

typedef  unsigned long  int  ub4;   /* unsigned 4-byte quantities */
typedef  unsigned       char ub1;   /* unsigned 1-byte quantities */

/* how many powers of 2's worth of buckets we use */
unsigned int hashpower = 24;
int collision=0;
#define hashsize(n) ((ub4)1<<(n))
#define hashmask(n) (hashsize(n)-1)
#define ITEM_key(item) (((char*)&((item)->data)) \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0))

long int NKeys=1000000;
#define NTest 100000
typedef struct _stritem {
    /* Protected by LRU locks */
//    struct _stritem *next;
//    struct _stritem *prev;
    /* Rest are protected by an item lock */
    struct _stritem *h_next;    /* hash chain next */
//    rel_time_t      time;       /* least recent access */
//    rel_time_t      exptime;    /* expire time */
//    int             nbytes;     /* size of data */
//    unsigned short  refcount;
//    uint8_t         nsuffix;    /* length of flags-and-length string */
//    uint8_t         it_flags;   /* ITEM_* above */
//    uint8_t         slabs_clsid;/* which slab class we're in */
    char *key;
    uint32_t         nkey;       /* key length, w/terminating null and padding */
    uint32_t        vn;         /* version number */ 
    /* this odd type prevents type-punning issues when we do
     * the little shuffle to save space when not using CAS. */
//    union {
//        uint64_t cas;
//        char end;
//    } data[];
    /* if it_flags & ITEM_CAS we have 8 bytes CAS */
    /* then null-terminated key */
    /* then " flags length\r\n" (no terminating null) */
    /* then data with terminating \r\n (no terminating null; it's binary!) */
} item;

static item** primary_hashtable = 0;

static unsigned int hash_items = 0;

void assoc_init(const int hashtable_init) {
    if (hashtable_init) {
        hashpower = hashtable_init;
    }
    primary_hashtable = calloc(hashsize(hashpower), sizeof(void *));
    if (! primary_hashtable) {
        fprintf(stderr, "Failed to init hashtable.\n");
        exit(EXIT_FAILURE);
    }
//    STATS_LOCK();
//    stats.hash_power_level = hashpower;
//    stats.hash_bytes = hashsize(hashpower) * sizeof(void *);
//    STATS_UNLOCK();
}

item *assoc_find(const char *key, const size_t nkey, const uint32_t hv) {
    item *it;
//    unsigned int oldbucket;

//    if (expanding &&
//        (oldbucket = (hv & hashmask(hashpower - 1))) >= expand_bucket)
//    {
//        it = old_hashtable[oldbucket];
//    } else {
        it = primary_hashtable[hv & hashmask(hashpower)];
//    }
    item *ret = NULL;
    int depth = 0;
    while (it) {
        collision++;
        if ((nkey == it->nkey) && (memcmp(key, it->key, nkey) == 0)) {
            ret = it;
            break;
        }
        it = it->h_next;
        ++depth;
    }
//    MEMCACHED_ASSOC_FIND(key, nkey, depth);
    return ret;
}

/* returns the address of the item pointer before the key.  if *item == 0,
   the item wasn't found */

static item** _hashitem_before (const char *key, const size_t nkey, const uint32_t hv) {
    item **pos;
//    unsigned int oldbucket;

//    if (expanding &&
//        (oldbucket = (hv & hashmask(hashpower - 1))) >= expand_bucket)
//    {
//        pos = &old_hashtable[oldbucket];
//    } else {
        pos = &primary_hashtable[hv & hashmask(hashpower)];
//    }

    while (*pos && ((nkey != (*pos)->nkey) || memcmp(key, (*pos)->key, nkey))) {
        pos = &(*pos)->h_next;
    }
    return pos;
}

/* Note: this isn't an assoc_update.  The key must not already exist to call this */
int assoc_insert(item *it, const uint32_t hv) {
//    unsigned int oldbucket;

//    assert(assoc_find(ITEM_key(it), it->nkey) == 0);  /* shouldn't have duplicately named things defined */

//    if (expanding &&
//        (oldbucket = (hv & hashmask(hashpower - 1))) >= expand_bucket)
//    {
//        it->h_next = old_hashtable[oldbucket];
//        old_hashtable[oldbucket] = it;
//    } else {
        it->h_next = primary_hashtable[hv & hashmask(hashpower)];
        primary_hashtable[hv & hashmask(hashpower)] = it;
//    }

//    pthread_mutex_lock(&hash_items_counter_lock);
    hash_items++;
//    if (! expanding && hash_items > (hashsize(hashpower) * 3) / 2) {
//        assoc_start_expand();
//    }
//    pthread_mutex_unlock(&hash_items_counter_lock);

//    MEMCACHED_ASSOC_INSERT(ITEM_key(it), it->nkey, hash_items);
    return 1;
}

void assoc_delete(const char *key, const size_t nkey, const uint32_t hv) {
    item **before = _hashitem_before(key, nkey, hv);

    if (*before) {
        item *nxt;
//        pthread_mutex_lock(&hash_items_counter_lock);
        hash_items--;
//        pthread_mutex_unlock(&hash_items_counter_lock);
        /* The DTrace probe cannot be triggered as the last instruction
         * due to possible tail-optimization by the compiler
         */
//        MEMCACHED_ASSOC_DELETE(key, nkey, hash_items);
        nxt = (*before)->h_next;
        (*before)->h_next = 0;   /* probably pointless, but whatever. */
        *before = nxt;
        return;
    }
    /* Note:  we never actually get here.  the callers don't delete things
       they can't find. */
    assert(*before != 0);
}

int    time_substract(struct timeval *result, struct timeval *begin,struct timeval *end)
{

    if(begin->tv_sec > end->tv_sec)    
      return -1;

    if((begin->tv_sec == end->tv_sec) && (begin->tv_usec > end->tv_usec))
      return -2;

    result->tv_sec    = (end->tv_sec - begin->tv_sec);
    result->tv_usec    = (end->tv_usec - begin->tv_usec);
    if(result->tv_usec < 0)
    {
        result->tv_sec--;
        result->tv_usec += 1000000;
    }
    return 0;
}

int main(int argc, char *argv[]){
    int randkey,i;
    int keys[NTest];
    char akeys[NTest][30];
    char buf[255];
    item *it_new, *it;
    uint32_t hv;
    FILE *fd,*fd1;
    struct timeval t_start,t_end,t_diff;
//gettimeofday(&t_start, NULL);
    hashpower = atoi(argv[1]);
    NKeys = atoi(argv[2]);
    assoc_init(hashpower);
/*
    sprintf(buf, "%ld", rand());
    printf("%s %d\n",buf,strlen(buf));
    fd1=fopen("test.txt","w"); 
    fprintf(fd1,"%s\n",buf);
    fclose(fd1);
    fd1=fopen("test.txt","r");
    fscanf(fd1, "%s", buf);
    printf("%s %d\n",buf,strlen(buf));
*/
collision=0;
printf("Very efficient!\n");
//    fd = fopen("keys.txt","w");
    for(i=0;i<NKeys;i++){
       it_new = (item *)malloc(sizeof(item));
       sprintf(buf, "%ld", rand());
//       printf("%s\n",buf);
//       fprintf(fd,"%s\n",buf);
       it_new->key = (char *)malloc(sizeof(char)*strlen(buf));
       it_new->nkey = strlen(buf);
       it_new->vn = 0;
       memcpy(it_new->key,buf,strlen(buf));
       hv = MurmurHash3_x86_32(it_new->key,it_new->nkey);
       it = assoc_find(it_new->key,it_new->nkey, hv);
       if(it==NULL){
         assoc_insert(it_new,hv);
//         printf("insert success!\n");  
       }else{
         free(it_new->key);
         free(it_new);
//        collision++;
       }
    }
//    fclose(fd);
//    fd = fopen("keys.txt","r");
//    fscanf(fd,"%s",buf);
//    printf("%s\n",buf);
    for(i=0;i<NTest;i++){
    randkey = rand();
//    printf("rand():%d\n",randkey);
    keys[i] = randkey;
//    it_new = (item *)malloc(sizeof(item));
//    fscanf(fd,"%s",buf);
    sprintf(akeys[i],"%ld",randkey);
//    it_new->key = &akeys[i];
//    printf("akeys[%d]:%s\n",i,akeys[i]);
//    printf("sizeof():%d\n",sizeof(akeys[i]));
//    memcpy(it_new->key,akeys[i],sizeof(akeys[i]));
//    it_new->nkey = sizeof(akeys[i]);
//    it_new->vn = 0;
//    printf("item:%s,%d\n",it_new->key, it_new->nkey);
//    hv = MurmurHash3_x86_32(it_new->key, it_new->nkey);
//    it = assoc_find(it_new->key, it_new->nkey, hv);
//    if(it){
//        printf("Find the item key:%s\n", it->key);
//    }
//    else{
//        assoc_insert(it_new,hv);
//        printf("insert item: %s\n", it_new->key);
//        printf("hv:%d\n",hv);
//    }
    }
//    fclose(fd);

    memset(&t_start,0,sizeof(struct timeval));
    memset(&t_end,0,sizeof(struct timeval));
    memset(&t_diff,0,sizeof(struct timeval));

gettimeofday(&t_start, NULL);
int j=0;
    for(i=0;i<NTest;i++){
//        sprintf(akey,"%d",keys[i]);
        hv = MurmurHash3_x86_32(akeys[i],strlen(akeys[i]));
        it=assoc_find(akeys[i], strlen(akeys[i]),hv);
        if(it==NULL){
//            printf("Failed: can not find key: %s\n",akeys[i]);
//            printf("hv:%d\n",hv);
        //printf("Not Find!\n");
           j++;
        }
        else{
//            printf("Find!\n");
        }
    }
gettimeofday(&t_end, NULL);
printf("Very efficient!\n");
time_substract(&t_diff,&t_start,&t_end);
printf("time cost is: %u s, %u us.\n", t_diff.tv_sec, t_diff.tv_usec);
printf("Ntest: %d keys not find!\n",j);    
printf("Number of collisions:%d\n",collision); 
    return 0;
}

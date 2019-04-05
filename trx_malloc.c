/*
 * Authors:
 * + Andrea Fioraldi <andreafioraldi@gmail.com>
 * + Pietro Borrello <pietro.borrello95@gmail.com>
 *
 * License: BSD 2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define SBRK_INCR 4096

#define NBINS 0x80
#define NFASTBINS 7

#define MINSIZE 0x20
#define MAX_FAST 0x80

#define FASTBIN_CONSOLIDATION_THRESHOLD 1024

#define SIZE_SZ sizeof(size_t)

#define IS_MMAPPED 0x2
#define PREV_INUSE 0x1

#define offsetof(type, field) ((unsigned long)&(((type*)(0))->field))

#define chunk2mem(c) ((void*)((char*)(c) + 2 * SIZE_SZ))
#define mem2chunk(mem) ((struct malloc_chunk*)((char*)(mem)-2 * SIZE_SZ))
// last 3 bits are for flags
#define chunksize(c) ((c)->size - ((c)->size & 0x7))

#define request2size(req)             \
  (((req) + SIZE_SZ < MINSIZE) \
       ? MINSIZE                      \
       : (((req) + SIZE_SZ + (2 * SIZE_SZ) - 1) & -(2 * SIZE_SZ)))
#define size2bin(s) (((s) >> 4) - 2)

#define next_by_mem(c) (struct malloc_chunk*)((char*)(c) + chunksize(c))
#define next_by_off(c, off) (struct malloc_chunk*)((char*)(c) + (off))
#define prev_by_mem(c) (struct malloc_chunk*)((char*)(c) - (c)->prev_size)

#define unset_prev_inuse(c) ((c)->size - ((c)->size & PREV_INUSE))
#define set_prev_inuse(c) ((c)->size |= PREV_INUSE)
#define set_mmapped(c) ((c)->size |= IS_MMAPPED)

#define is_mmapped(c) ((c)->size & IS_MMAPPED)
#define prev_inuse(c) ((c)->size & PREV_INUSE)

#define bin_at(i)                                     \
  ((struct malloc_chunk*)((char*)&arena.bins[i * 2] - \
                          offsetof(struct malloc_chunk, fd)))

/* Take a chunk off a bin list */

#define unlink(P, BK, FD) \
  do {                    \
    FD = P->fd;           \
    BK = P->BK;           \
    FD->bk = BK;          \
    BK->fd = FD;          \
  } while (0)

#ifdef DEBUG
#define debug(...) fprintf(stderr, __VA_ARGS__)
#else
#define debug(...) do {} while(0)
#endif

#define error(m)                       \
  do {                                 \
    fprintf(stderr, "error: %s\n", m); \
    abort();                           \
  } while (0)

/* A chunk in memory is like:

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                     |0|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list [U]         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list [U]        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Space [U]                                         .
            .                                                               .
            .                                                               .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes [U]                       |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |0|M|P|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Last 3 bits of size are flags:
    - last bit (P): Previous chunk in memory is in use
    - 2nd last bit (M): Chunk is mmapped
    - 3rd last bit: Not used, but used by ptmalloc

    When allocated, All the parts marked with [U] are user data insrted in the
    returned memory by malloc(). They are metadata only when the chunk is free.

*/

struct malloc_chunk {

  size_t prev_size;
  size_t size;

  struct malloc_chunk* fd;
  struct malloc_chunk* bk;
};

struct malloc_state {

  /* Fastbin are NULL terminated single linked list.
    
    size2bin give us the offset (same for bins).

    There are 7 fastbin in trxmalloc and they are mapped in this way:

     - malloc(0..24) will have size = 32 -> fastbin 0
     - malloc(25..40) will have size = 48 -> fastbin 1
     - malloc(41..56) will have size = 64 -> fastbin 2
     - malloc(57..72) will have size = 80 -> fastbin 3
     - malloc(73..88) will have size = 96 -> fastbin 4
     - malloc(89..104) will have size = 112 -> fastbin 5
     - malloc(105..120) will have size = 128 -> fastbin 6 */
  
  struct malloc_chunk* fastbins[NFASTBINS];

  struct malloc_chunk* top;

  /* In these bins a new free chunk is inserted at the front and requests are
     served from the back in a FIFO spirit.
  
     Each bin is treated as chunk but only fd and bk are really used so size
     and prev_size are mapped to the space of the previous bin (yeah a bit
     messy but ptmalloc works in this way).

     bin N-1 -> +-+-+-+-+-+-+-+-+-+-+-+-+-+
                |   N-1 fd (N prev_size)  |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+
                |   N-1 bk (N size)       |
      bin N ->  +-+-+-+-+-+-+-+-+-+-+-+-+-+
                |   N fd                  |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+
                |   N bk                  |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+

      When a bin is empty fd and bk points to the start of the bin interpreted
      as chunk. So, if the bin N is empty, N fd and bk are the address of
      bin N-1 (look at the initialization code in trx_malloc() and the bin_at
      macro). */

  struct malloc_chunk* bins[NBINS * 2 - 2];
};

/* Thread safety? What is thread safety? TODO */

struct malloc_state arena;

/* Malloc hooks are function pointers that can replace malloc/realloc/free
   when they are != NULL (and this is pornograhic for an attacker ;) )*/

void *(*__trx_malloc_hook)(size_t);
void *(*__trx_realloc_hook)(void*, size_t);
void (*__trx_free_hook)(void*);

/* Utility function to serve mmapped chunks */

static void* _trx_mmap_chunk(size_t size) {

  size_t sz = request2size(size) + SIZE_SZ;

  struct malloc_chunk *victim =
      mmap(0, sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (victim == (struct malloc_chunk*)MAP_FAILED)
    return NULL;

  victim->size = sz;
  set_mmapped(victim);
  
  debug(" = %p\n", chunk2mem(victim));

  return chunk2mem(victim);
}

void* trx_malloc(size_t size) {

  debug("malloc(%lu)", size);
  
  if (__trx_malloc_hook)
    return __trx_malloc_hook(size);

  size_t sz = request2size(size);
  size_t idx = size2bin(sz);
  struct malloc_chunk* victim;

  if (sz > NBINS * 0x10)
    return _trx_mmap_chunk(size);

  if (!arena.top) {

    /* Initialize heap.
       sbrk(0) returns the current heap end. */

    void* initial = sbrk(0);
    if (initial == (void*)-1)
      error("trx_malloc(): sbrk() failed, very very bad");

    if (sbrk(SBRK_INCR) == (void*)-1)
      error("trx_malloc(): sbrk() failed, very very bad");

    /* Intialize arena.bins. Bins are double linked.
       As simplification (from ptmalloc) bins acts like chunks but in order to
       save space only fd and bk are used.
       When empty, bin->fd = bin->bk = bin */

    size_t i;
    for (i = 0; i < NBINS; ++i)
      bin_at(i)->fd = bin_at(i)->bk = bin_at(i);

    struct malloc_chunk* new_top = initial;
    new_top->size = (SBRK_INCR - SIZE_SZ) | 1;
    arena.top = new_top;

    goto allocate_from_top;
  }

  /* From fastbin if avaiable */

  if (sz <= MAX_FAST) {

    victim = arena.fastbins[idx];
    if (victim) {
      
      debug("removing %p from fastbin %lu\n", victim, idx);

      set_prev_inuse(next_by_off(victim, sz));
      arena.fastbins[idx] = victim->fd;
      
      debug(" = %p\n", chunk2mem(victim));

      return chunk2mem(victim);
    }
  }

  /* From bins if avaiable with exact size */

  if ((victim = bin_at(idx)->bk) != bin_at(idx)) {

    struct malloc_chunk* bck = victim->bk;

    set_prev_inuse(next_by_off(victim, sz));
    bin_at(idx)->bk = bck;
    bck->fd = bin_at(idx);
    
    debug(" = %p\n", chunk2mem(victim));
    
    return chunk2mem(victim);
  }

  /* From bins if avaiable of greater size */

  idx += 1;

  while (idx < NBINS - 1) {

    if ((victim = bin_at(idx)->bk) != bin_at(idx)) {

      /* TODO decrease size of this chunk when the requested size is less than
         bin size and create a remainder free chunk that must be inserted in
         the correct bin.

         e.g. with sz = 0x20 and chunksize(victim) = 0x100
              set victim size to 0x20, create a remainder with size 0x80
              and insert into bin_at(size2bin(0x80)) */

      struct malloc_chunk* bck = victim->bk;

      set_prev_inuse(next_by_mem(victim));
      bin_at(idx)->bk = bck;
      bck->fd = bin_at(idx);

      debug(" = %p\n", chunk2mem(victim));
      
      return chunk2mem(victim);
    }

    idx += 1;
  }

  /* Allocate from top chunk */

allocate_from_top:

  victim = arena.top;
  if (victim->size >= sz) {

    size_t old_sz = chunksize(victim);
    victim->size = sz | PREV_INUSE;

    struct malloc_chunk* new_top = next_by_off(victim, sz);
    new_top->size = (old_sz - sz) | PREV_INUSE;
    arena.top = new_top;

    debug(" = %p\n", chunk2mem(victim));
    
    return chunk2mem(victim);
  }

  /* Request memory to the kernel */

  if (sbrk(SBRK_INCR) == (void*)-1)
    error("trx_malloc(): sbrk() failed, very very bad");

  arena.top->size += SBRK_INCR;

  /* Retry with more memory from the OS */

  return trx_malloc(size);
}

/* Tears down chunks in fastbins */

void _trx_malloc_consolidate() {

  /* TODO consolidate bulk merge fastbins in a larger chunk.
     Traverse the fastbins, see if chunks are contiguos in memory, then merge
     them and inserted the new chunk in the proper bin.
     Remind that the top chunk cannot have a freed chunk as previous chunk */

  return;
}

void trx_free(void* ptr) {

  debug("free(%p)\n", ptr);
 
  if (__trx_free_hook) {
    __trx_free_hook(ptr);
    return;
  }

  /* free(0) is a no-op to be POSIX compliant */

  if (!ptr)
    return;

  struct malloc_chunk* ck = mem2chunk(ptr);
  size_t sz = chunksize(ck);

  if (is_mmapped(ck)) {

    munmap(ck, sz);
    return;
  }

  size_t idx = size2bin(sz);

  if (sz <= MAX_FAST) {

    /* Unset prev_inuse of the next chunk if it is not the top chunk,
       otherwise consolidate with the top chunk. Top chunk prev_inuse is
       always set in this way */

    if (next_by_off(ck, sz) != arena.top) {

      unset_prev_inuse(next_by_off(ck, sz));

      /* Insert at the top of the fastbin and set fd to the old top */

      struct malloc_chunk* old_p = arena.fastbins[idx];
      arena.fastbins[idx] = ck;
      ck->fd = old_p;

    } else {

      /* Update arena.top. Note that prev_inuse already in arena.top->size */

      debug("consolidating %p with top\n", ptr);

      ck->size = chunksize(ck) + arena.top->size;
      arena.top = ck;
    }

  } else {

    /* When freeing a large size (not very large in this allocator) consolidate
       the possibily sourrunding fast chunks.
       
    if(sz >= FASTBIN_CONSOLIDATION_THRESHOLD)
      _trx_malloc_consolidate(); */

    struct malloc_chunk* p;
    struct malloc_chunk *fd, *bk;

    /* Consolidate backward */

    while (!prev_inuse(ck)) {

      p = prev_by_mem(ck);

      /* Fast chunks are consolidated in bulk in malloc_consolidate() */

      if (chunksize(p) <= MAX_FAST)
        break;

      unlink(p, fd, bk);

      p->size += chunksize(ck);
      ck = p;
    }

    p = next_by_mem(ck);

    /* Consolidate forward */

    while (p != arena.top && chunksize(p) > MAX_FAST &&
           !prev_inuse(next_by_mem(p))) {

      unlink(p, fd, bk);

      ck->size += chunksize(p);

      p = next_by_mem(p);
    }

    /* Consolidate with top chunk */

    if (p == arena.top) {

      ck->size = chunksize(ck) + arena.top->size;
      arena.top = ck;

      return;
    }

    sz = chunksize(ck);
    idx = size2bin(sz);

    fd = bin_at(idx)->fd;

    bin_at(idx)->fd = ck;
    ck->bk = bin_at(idx);
    ck->fd = fd;
    fd->bk = ck;
  }

  return;
}

void* trx_calloc(size_t nmemb, size_t size) {

  /* Ignurant implementation, maybe TODO, maybe left ignurant */

  size_t s = nmemb * size;
  void* p = malloc(s);

  /* mmap() returns zeroed memory, do not steal the work to the kernel and
     avoid to fill with zero again */

  if (!is_mmapped(mem2chunk(p)))
    memset(p, 0, s);

  return p;
}

size_t trx_malloc_usable_size(void* ptr) {

  struct malloc_chunk* c = mem2chunk(ptr);
  return c->size - SIZE_SZ;
}

void* trx_realloc(void* ptr, size_t size) {

  if (__trx_realloc_hook)
    return __trx_realloc_hook(ptr, size);

  /* TODO reallocate chunk if the new requested size does not fit in
     trx_malloc_usable_size(ptr), otherwise returns ptr. */

  /* realloc(0, size) fallbacks to malloc(size) to be POSIX copliant */

  if (ptr == NULL)
    return trx_malloc(size);

  /* Very very dirty */

  void* p = trx_malloc(size);
  memcpy(p, ptr, trx_malloc_usable_size(ptr));
  trx_free(ptr);

  return p;
}

/* TODO memalign function is missing :( */


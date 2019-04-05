#ifndef __TRX_MALLOC_H__
#define __TRX_MALLOC_H__

#include <stdio.h>

extern void *(__trx_malloc_hook)(size_t);                                              
extern void *(__trx_realloc_hook)(void*, size_t);                                      
extern void (__trx_free_hook)(void*);

void *trx_malloc(size_t size);
void trx_free(void *ptr);
void *trx_calloc(size_t nmemb, size_t size);
void *trx_realloc(void *ptr, size_t size);
size_t trx_malloc_usable_size(void* ptr);

#endif

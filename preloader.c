#include "trx_malloc.h"

void *malloc(size_t size) {
  return trx_malloc(size);
}

void free(void *ptr) {
  trx_free(ptr);
}

void *calloc(size_t nmemb, size_t size) {
  return trx_calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size) {
  return trx_realloc(ptr, size);
}

size_t malloc_usable_size(void* ptr) {
  return trx_malloc_usable_size(ptr);
}

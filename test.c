/*
 * Authors:
 * + Andrea Fioraldi <andreafioraldi@gmail.com>
 * + Pietro Borrello <pietro.borrello95@gmail.com>
 *
 * License: BSD 2-Clause
 */

#include "trx_malloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#define print(...) fprintf(stderr, __VA_ARGS__)
#define NCHUNKS 128
#define TRIES 2048

int main(int argc, char** argv) {
  /*test fastbin recycle*/
  char* a = trx_malloc(20);
  print("a: %p\n", a);
  char *a1 = trx_malloc(20);
  print("a1: %p\n", a1);

  trx_free(a);

  char* b = trx_malloc(20);
  print("b: %p\n", b);

  assert(a == b);
  /*---*/

  /*test smallbin recycle*/
  char* c = trx_malloc(200);
  print("c: %p\n", c);
  char *c1 = trx_malloc(200);
  print("c1: %p\n", c1);

  trx_free(c);

  char* d = trx_malloc(200);
  print("d: %p\n", d);

  assert(c == d);
  /*---*/

  /* test smallbin top chunk consolidation */
  char* e = trx_malloc(200);
  print("e: %p\n", e);

  char *f = trx_malloc(200);
  print("f: %p\n", f);

  trx_free(e);
  trx_free(d);

  char *g = trx_malloc(20);
  print("g: %p\n", g);

  assert(g == e);
  /*---*/

  /*test smallbin fifo*/
  char *h = trx_malloc(200);
  print("h: %p\n", h);

  char *i = trx_malloc(200);
  print("i: %p\n", i);

  char *j = trx_malloc(20);
  print("j: %p\n", j);

  trx_free(h);
  trx_free(i);

  char *k = trx_malloc(200);
  print("k: %p\n", k);
  char *l = trx_malloc(200);
  print("l: %p\n", l);

  assert(k == h);
  assert(l == i);
  /*---*/

  /*test fastbin stack*/
  char *m = trx_malloc(20);
  print("m: %p\n", m);
  char *n = trx_malloc(20);
  print("n: %p\n", n);
  char *n1 = trx_malloc(20);
  print("n1: %p\n", n1);

  trx_free(m);
  trx_free(n);

  char *o = trx_malloc(20);
  print("o: %p\n", o);
  char *p = trx_malloc(20);
  print("p: %p\n", p);

  assert(o == n);
  assert(p == m);
  /*---*/

  /* fuzzy: will it crash? */
  char *chunks[NCHUNKS];
  memset(chunks, 0, sizeof(char *) * NCHUNKS);

  unsigned long seed;
  if(argc > 1) seed = atol(argv[1]);
  else seed = time(0);
  
  FILE *fp = fopen("./last_seed", "w");
  if (fp != NULL)
  {
    fprintf(fp, "%lu\n", seed);
    fclose(fp);
  }

  srand(seed);
  for(int _i = 0; _i < TRIES; _i++)
  {
    int index = rand() % NCHUNKS;
    if (rand() % 2)
    {
      int size = rand() % 0x1000;
      unsigned char rand_char = rand() % 256;
      chunks[index] = trx_malloc(size);
      memset(chunks[index], rand_char, size);
      chunks[index][size-1] = 0;
    } else {
      if(chunks[index])
      {
        trx_free(chunks[index]);
        chunks[index] = NULL;
      }
    }
  }

  /* content check */
  for (int _i = 0; _i < NCHUNKS; _i++)
  {
    if (chunks[_i])
    {
      for (int _j = 0;  chunks[_i][_j]; _j++)
      {
        assert(chunks[_i][_j] == chunks[_i][0]);
      }
    }
  }

    /*---*/
}








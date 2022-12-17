all: preloader

preloader:
	cc -m32 -fPIC -shared -g preloader.c trx_malloc.c -o libtrxmalloc.so

debug: 
	cc -m32 -fPIC -shared -g -DDEBUG preloader.c trx_malloc.c -o libtrxmalloc.so

test: debug
	cc -m32 -DDEBUG test.c -g -o test -L . -l trxmalloc -Wl,-rpath=.

clean:
	rm -f libtrxmalloc.so test last_seed

CC = gcc
CFLAGS = -g -Wall -std=c11

libinterceptor.so: interceptor.c
	$(CC) $(CFLAGS) interceptor.c -o libinterceptor.so -Wl,-soname=libinterceptor.so -shared -fPIC

clean:
	rm -f libinterceptor.so

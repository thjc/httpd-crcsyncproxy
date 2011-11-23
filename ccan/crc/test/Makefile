EXTRA_FLAGS=-D_LARGEFILE64_SOURCE -Wall -Werror -g -fPIC -I. -I../.. -O3
CFLAGS=$(EXTRA_FLAGS)
CXXFLAGS=$(EXTRA_FLAGS)
LDFLAGS=

test_crc64iso: test_crc64iso.o ../crc.o
	gcc $^ -o $@

../crc.o: ../crc.c ../crc.h

clean:
	rm test_crc64iso *.o ../*.o


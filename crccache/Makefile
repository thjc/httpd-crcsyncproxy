#APACHE_PATH=../apache
#MOD_PATH=$(APACHE_PATH)/modules
#CACHE_PATH=$(MOD_PATH)/cache

CCAN_PATH=../ccan
SOURCE_ROOT=..

EXTRA_FLAGS=-D_LARGEFILE64_SOURCE -Wall -Werror -g -fPIC -I/usr/include/apache2 -I. -I$(SOURCE_ROOT) -I$(CCAN_PATH) -O3
CFLAGS=`apr-config --cflags --includes` $(EXTRA_FLAGS)
CXXFLAGS=`apr-config --cppflags --includes` $(EXTRA_FLAGS)
LDFLAGS=`apr-1-config --link-ld --libs` -laprutil-1 -lz -lcrypto

all: mod_crccache_client.so mod_crccache_server.so benchmark test_hash_small_invokations

CACHE_SRC=cache/cache.o cache/cache_cache.o \
cache/cache_hash.o cache/cache_pqueue.o \
cache/cache_util.o cache/cache_storage.o

#cache/mod_cache.o
#cache/mod_disk_cache.o
#cache/mod_file_cache.o
#cache/mod_socache_dbm.c
#cache/mod_socache_dc.c
#cache/mod_socache_memcache.c
#cache/mod_socache_shmcb.c


%.so: %.o ap_wrapper.o $(CCAN_PATH)/crc/crc.o $(CCAN_PATH)/crcsync/crcsync.o $(CACHE_SRC)
	gcc $^ -o $@ $(LDFLAGS) -shared

clean:
	rm -rf *.so *.o $(CCAN_PATH)/crc/crc.o $(CCAN_PATH)/crcsync/crcsync.o

benchmark: benchmark.o $(CCAN_PATH)/crc/crc.o $(CCAN_PATH)/crcsync/crcsync.o
	gcc $^ -o $@ -lgcrypt -lgpg-error -lz

test_hash_small_invokations: test_hash_small_invokations.o $(CCAN_PATH)/crc/crc.o $(CCAN_PATH)/crcsync/crcsync.o
	gcc $^ -o $@

restart:
	sudo /etc/init.d/apache2 restart
 

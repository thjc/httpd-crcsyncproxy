#APACHE_PATH=../apache
#MOD_PATH=$(APACHE_PATH)/modules
#CACHE_PATH=$(MOD_PATH)/cache

CCAN_PATH=../ccan
SOURCE_ROOT=..

EXTRA_FLAGS=-D_LARGEFILE64_SOURCE -Wall -Werror -g -fPIC -I/usr/include/apache2 -I. -I$(SOURCE_ROOT) -I$(CCAN_PATH) -O3
CFLAGS=`apr-config --cflags --includes` $(EXTRA_FLAGS)
CXXFLAGS=`apr-config --cppflags --includes` $(EXTRA_FLAGS)
LDFLAGS=`apr-1-config --link-ld --libs` -laprutil-1 -lz

all: mod_crccache_client.so mod_crccache_server.so benchmark test_hash_small_invokations done

CCAN_CRC=$(CCAN_PATH)/crc/crc.o $(CCAN_PATH)/crcsync/crcsync.o 

COMMON=ap_log_helper.o $(CCAN_CRC) 

CACHE=cache/cache.o cache/cache_cache.o \
cache/cache_hash.o cache/cache_pqueue.o \
cache/cache_util.o cache/cache_storage.o

mod_crccache_client.so: mod_crccache_client.o $(COMMON) $(CACHE) rmm_hash.o mod_crccache_client_find_similar.o
	gcc $^ -o $@ $(LDFLAGS) -shared

mod_crccache_server.so: mod_crccache_server.o $(COMMON)
	gcc $^ -o $@ $(LDFLAGS) -shared

clean:
	rm -rf *.so *.o $(COMMON) $(CACHE)

benchmark: benchmark.o $(CCAN_PATH)/crc/crc.o $(CCAN_PATH)/crcsync/crcsync.o
	gcc $^ -o $@ $(LDFLAGS)

test_hash_small_invokations: test_hash_small_invokations.o $(CCAN_PATH)/crc/crc.o $(CCAN_PATH)/crcsync/crcsync.o
	gcc $^ -o $@

restart:
	sudo /etc/init.d/apache2 restart
 
done:
	echo "All done"

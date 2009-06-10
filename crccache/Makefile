APACHE_PATH=../
MOD_PATH=$(APACHE_PATH)/modules
CACHE_PATH=$(MOD_PATH)/cache

CCAN_PATH=../ccan

EXTRA_FLAGS=-D_LARGEFILE64_SOURCE -Wall -Werror -g -fPIC -I/usr/include/apache2 -I$(CACHE_PATH) -I$(CCAN_PATH) -I$(APACHE_PATH)
CFLAGS=`apr-config --cflags --includes` $(EXTRA_FLAGS)
CXXFLAGS=`apr-config --cppflags --includes` $(EXTRA_FLAGS)
LDFLAGS=`apr-config --ldflags` -lapr-1 -laprutil-1

all: mod_crccache_client.so mod_crccache_server.so test_hashes

%.so: %.o ap_wrapper.o crccache.o $(CCAN_PATH)/crc/crc.o $(CCAN_PATH)/crcsync/crcsync.o
	gcc $^ -o $@ -shared

test_hashes: test_hashes.o crccache.o
	gcc $^ -o $@ $(LDFLAGS)

clean:
	rm -rf *.so *.o
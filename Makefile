PKG_BUILDDIR=pkgtmp
VERSION=0.1.0
PACKAGE_NAME=libapache2-mod-crccache

PREFIX?=$(DESTDIR)/

CCAN_PATH=ccan

all:
	make -C crccache

clean:
	make -C crccache clean
	rm -rf *.orig.tar.gz
	rm -rf $(PKG_BUILDDIR)

dist:
	git archive --format=tar --prefix=$(PACKAGE_NAME)-$(VERSION)/ HEAD Makefile crccache ccan apache/modules/cache  | gzip > $(PACKAGE_NAME)_$(VERSION).orig.tar.gz

deb: dist
	# first unpack the source and copy in the deb dir
	rm -rf $(PKG_BUILDDIR)
	mkdir $(PKG_BUILDDIR)
	cp $(PACKAGE_NAME)_$(VERSION).orig.tar.gz $(PKG_BUILDDIR)
	cd $(PKG_BUILDDIR); tar -xzf $(PACKAGE_NAME)_$(VERSION).orig.tar.gz
	cp -r debian $(PKG_BUILDDIR)/$(PACKAGE_NAME)-$(VERSION)
	
	# then we need to build the deb source archive
	cd $(PKG_BUILDDIR)/$(PACKAGE_NAME)-$(VERSION); debuild -S -uc -us	

debbin: deb
	cd $(PKG_BUILDDIR)/$(PACKAGE_NAME)-$(VERSION); debuild -uc -us

install:
	echo INSTALL $(PREFIX)

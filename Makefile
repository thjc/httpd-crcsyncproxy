PKG_BUILDDIR=pkgtmp
VERSION=0.1.0

all:
	make -C crccache

clean:
	make -C crccache clean
	rm -rf *.orig.tar.gz
	rm -rf $(PKG_BUILDDIR)

dist:
	git archive --format=tar --prefix=crccache-$(VERSION)/ HEAD crccache ccan | gzip > crccache_$(VERSION).orig.tar.gz

deb: dist
	mkdir $(PKG_BUILDDIR)
	cd $(PKG_BUILDDIR); tar -xzf crccache-$(VERSION).tar.gz
	cp $(PKG_BUILDDIR)/crccache-$(VERSION).tar.gz $(PKG_BUILDDIR)/crccache_$(VERSION).orig.tar.gz
	#cp -r debian $(PKG_BUILDDIR)/crccache-$(VERSION)

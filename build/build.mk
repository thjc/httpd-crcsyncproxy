# ====================================================================
# The Apache Software License, Version 1.1
#
# Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
# reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The end-user documentation included with the redistribution,
#    if any, must include the following acknowledgment:
#       "This product includes software developed by the
#        Apache Software Foundation (http://www.apache.org/)."
#    Alternately, this acknowledgment may appear in the software itself,
#    if and wherever such third-party acknowledgments normally appear.
#
# 4. The names "Apache" and "Apache Software Foundation" must
#    not be used to endorse or promote products derived from this
#    software without prior written permission. For written
#    permission, please contact apache@apache.org.
#
# 5. Products derived from this software may not be called "Apache",
#    nor may "Apache" appear in their name, without prior written
#    permission of the Apache Software Foundation.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
# ====================================================================
#
# This software consists of voluntary contributions made by many
# individuals on behalf of the Apache Software Foundation.  For more
# information on the Apache Software Foundation, please see
# <http://www.apache.org/>.
#
# The build environment was provided by Sascha Schumann.
#

#
# Makefile to generate build tools
#

STAMP = buildmk.stamp

all: $(STAMP) generated_lists
	@if [ ! -d srclib/apr -o ! -f srclib/apr/build/apr_common.m4 ]; then \
	    echo "" ; \
	    echo "You don't have a srclib/apr/ subdirectory.  Please get one:" ; \
	    echo "" ; \
	    echo "   cd srclib" ; \
	    echo "   cvs -d :pserver:anoncvs@apache.org:/home/cvspublic login" ; \
	    echo "      (password 'anoncvs')" ; \
	    echo "   cvs -d :pserver:anoncvs@apache.org:/home/cvspublic co apr" ; \
	    echo "" ; \
	    exit 1; \
	fi
	@if [ ! -d srclib/apr-util -o ! -f srclib/apr-util/Makefile.in ]; then \
	    echo "" ; \
	    echo "You don't have a srclib/apr-util/ subdirectory.  Please get one:" ; \
	    echo "" ; \
	    echo "   cd srclib" ; \
	    echo "   cvs -d :pserver:anoncvs@apache.org:/home/cvspublic login" ; \
	    echo "      (password 'anoncvs')" ; \
	    echo "   cvs -d :pserver:anoncvs@apache.org:/home/cvspublic co apr-util" ; \
	    echo "" ; \
	    exit 1; \
	fi
	@$(MAKE) AMFLAGS=$(AMFLAGS) -s -f build/build2.mk

generated_lists:
	@libpath=`build/PrintPath libtoolize`; \
	if [ "x$$libpath" = "x" ]; then \
		echo "libtoolize not found in path"; \
		exit 1; \
	fi; 
	@echo config_m4_files = `find . -name config*.m4` > $@
	@n=`build/PrintPath libtoolize`; echo libtool_prefix = `dirname $$n`/.. >> $@

$(STAMP): build/buildcheck.sh
	@build/buildcheck.sh && touch $(STAMP)

snapshot:
	distname='$(DISTNAME)'; \
	if test -z "$$distname"; then \
		distname='apache2-snapshot'; \
	fi; \
	cd ..; \
	myname=`basename \`pwd\`` ; \
	cd .. && cp -rp $$myname $$distname; \
	cd $$distname/src; \
	find . -type l -exec rm {} \; ; \
	$(MAKE) AMFLAGS=--copy -f build/build.mk; \
	cd ../..; \
	tar cf $$distname.tar $$distname; \
	rm -rf $$distname $$distname.tar.*; \
	bzip2 -9 $$distname.tar; \
	bzip2 -t $$distname.tar.bz2

cvsclean:
	@for i in `find . -name .cvsignore`; do \
		(cd `dirname $$i` 2>/dev/null && rm -rf `cat .cvsignore` *.o *.a || true); \
	done
	@rm -f $(SUBDIRS) 2>/dev/null || true

.PHONY: generated_lists snapshot cvsclean

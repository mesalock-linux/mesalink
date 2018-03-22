ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS=
noinst_HEADERS=
lib_LTLIBRARIES=
noinst_LTLIBRARIES=
noinst_PROGRAMS=
include_HEADERS=
nobase_include_HEADERS=
DISTCLEANFILES=
EXTRA_DIST=

DISTCLEANFILES+= mesalink-config
EXTRA_DIST+= src
EXTRA_DIST+= rustls
EXTRA_DIST+= sct
EXTRA_DIST+= autogen.sh
EXTRA_DIST+= Cargo.toml
EXTRA_DIST+= Cargo.lock
EXTRA_DIST+= build.rs
EXTRA_DIST+= LICENSE

include src/include.am
include mesalink/include.am
include examples/include.am

install-exec-local:	install-generic-config

install-generic-config:
	$(mkinstalldirs) $(DESTDIR)$(bindir)
	$(INSTALL_SCRIPT) @GENERIC_CONFIG@ $(DESTDIR)$(bindir)

maintainer-clean-local:
	-cargo clean
	-rm -rf target
	-rm Makefile.in
	-rm Makefile
	-rm mesalink-config
	-rm libmesalink.la
	-rm aclocal.m4
	-rm -rf build-aux
	-rm -rf autom4te.cache
	-rm -rf target
	-rm configure
	-rm config.log
	-rm config.status
	-rm config.in
	-rm config.in~
	-rm m4/libtool.m4
	-rm m4/ltoptions.m4
	-rm m4/ltsugar.m4
	-rm m4/ltversion.m4
	-rm m4/lt~obsolete.m4
	-rm libtool
	-rm stamp-h1
	-rm -rf bogo/bogo
	-rm -rf bogo/runner.tar.gz

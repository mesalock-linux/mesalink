ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS=
noinst_HEADERS=
lib_LTLIBRARIES=
noinst_LTLIBRARIES=
noinst_PROGRAMS=
include_HEADERS=
nobase_include_HEADERS=

include src/include.am
include mesalink/include.am
include examples/include.am

maintainer-clean-local:
	-cargo clean
	-rm -rf target
	-rm Makefile.in
	-rm Makefile
	-rm aclocal.m4
	-rm -rf build-aux
	-rm -rf autom4te.cache
	-rm -rf target
	-rm configure
	-rm config.log
	-rm config.status
	-rm config.h
	-rm config.in
	-rm m4/libtool.m4
	-rm m4/ltoptions.m4
	-rm m4/ltsugar.m4
	-rm m4/ltversion.m4
	-rm m4/lt~obsolete.m4
	-rm libtool
	-rm stamp-h1
	-find . -type f -name '*~' -exec rm -f '{}' \;
	-find . -name ".libs" -exec rm -rf '{}' \;
	-find . -name ".dirstamp" -exec rm -rf '{}' \;

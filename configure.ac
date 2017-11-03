AC_INIT([mesalink], m4_esyscmd([grep version Cargo.toml | awk '{print $3}' | tr -d '"' | tr -d "\n"]), [jingyiming@baidu.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h:config.in])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST

AC_PREREQ([2.63])
AM_INIT_AUTOMAKE([1.11 -Wall -Werror foreign no-dependencies subdir-objects])

MESALINK_VERSION=$(grep ^version Cargo.toml | awk '{print $3}' | tr -d '"' | tr -d "\n")
AC_SUBST(MESALINK_VERSION)

LT_PREREQ([2.2])
LT_INIT([disable-static])
LT_LANG([C++])
LT_LANG([C])

AC_PROG_CC

DYLIB_EXTENSION=

case "${host_os}" in
    linux*)
        DYLIB_EXTENSION=so
        ;;
    cygwin*|mingw*)
        DYLIB_EXTENSION=dll
        ;;
    darwin*)
        DYLIB_EXTENSION=dylib
        ;;
    *)
        AC_MSG_ERROR(["OS $host_os is not supported"])
        ;;
esac

AC_SUBST(DYLIB_EXTENSION)

AC_CHECK_HEADERS([netdb.h netinet/in.h string.h sys/socket.h unistd.h])
AC_CHECK_FUNCS([gethostbyname memset socket])
AC_CHECK_PROG(CARGO, [cargo], [yes], [no])
AS_IF(test x$CARGO = xno,
    AC_MSG_ERROR([cargo is required])
)
AC_CHECK_PROG(RUSTC, [rustc], [yes], [no])
AS_IF(test x$RUSTC = xno,
    AC_MSG_ERROR([rustc is required])
)


AC_CONFIG_FILES([Makefile])
AC_OUTPUT

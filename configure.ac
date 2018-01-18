AC_INIT([mesalink], m4_esyscmd([grep version Cargo.toml | awk '{print $3}' | tr -d '"' | tr -d "\n"]), [jingyiming@baidu.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h:config.in])

: ${CFLAGS=""}

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
AC_PROG_CC_C_O
AC_PROG_INSTALL

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

OPTIMIZE_CFLAGS="-Os -ffunction-sections -fdata-sections -Wl,-dead_strip"
DEBUG_CFLAGS="-g -ggdb -O0 -Wall"

AX_DEBUG
AM_CONDITIONAL([CARGO_DEBUG], [test "x$ax_enable_debug" = "xyes"])
if test "$ax_enable_debug" = "yes"
then
    CFLAGS="$DEBUG_CFLAGS $CFLAGS"
else
    CFLAGS="$OPTIMIZE_CFLAGS $CFLAGS"
fi
AC_SUBST([CARGO_FEATURES], [--features ])
CARGO_FEATURES=$CARGO_FEATURES" \""

AC_ARG_ENABLE([errorstrings],
    [AS_HELP_STRING([--enable-errorstrings], [Enable error string table (default: enabled)])],
    [ ENABLE_ERROR_STRINGS=$enableval ],
    [ ENABLE_ERROR_STRINGS=yes ]
    )
if test "$ENABLE_ERROR_STRINGS" = "yes"
then
    CARGO_FEATURES=$CARGO_FEATURES" error_strings"
fi

AC_ARG_ENABLE([aesgcm],
    [AS_HELP_STRING([--enable-aesgcm], [Enable AES-GCM bulk encryption (default: enabled)])],
    [ ENABLE_AESGCM=$enableval ],
    [ ENABLE_AESGCM=yes ]
    )
if test "$ENABLE_AESGCM" = "yes"
then
    CARGO_FEATURES=$CARGO_FEATURES" aesgcm"
fi

AC_ARG_ENABLE([chachapoly],
    [AS_HELP_STRING([--enable-chachapoly], [Enable Chacha20Poly1305 bulk encryption (default: enabled)])],
    [ ENABLE_CHACHAPOLY=$enableval ],
    [ ENABLE_CHACHAPOLY=yes ]
    )
if test "$ENABLE_CHACHAPOLY" = "yes"
then
    CARGO_FEATURES=$CARGO_FEATURES" chachapoly"
fi

CARGO_FEATURES=$CARGO_FEATURES"\""

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "---"
echo "Running make clean ..."
make clean >/dev/null 2>&1

echo "---"
echo "Configuration summary for $PACKAGE_NAME version $VERSION"
echo ""
echo "   * Installation prefix:        $prefix"
echo "   * System type:                $host_vendor-$host_os"
echo "   * Host CPU:                   $host_cpu"
echo "   * C Compiler:                 $CC"
echo "   * C Flags:                    $CFLAGS"
echo "   * Debug enabled:              $ax_enable_debug"
echo "   * Warnings as failure:        $ac_cv_warnings_as_errors"
echo
echo "   Features "
echo "   * Error strings               $ENABLE_ERROR_STRINGS"
echo "   * AES-GCM                     $ENABLE_AESGCM"
echo "   * Chacha20-Poly1305           $ENABLE_CHACHAPOLY"
echo ""
echo "---"
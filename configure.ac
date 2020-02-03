AC_INIT([mesalink], m4_esyscmd([grep version Cargo.toml | head -n1 | awk '{print $3}' | tr -d '"' | tr -d "\n"]), [jingyiming@baidu.com])
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

AC_LANG([C])
AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_INSTALL
AM_PROG_AR
AC_PROG_AWK

LT_PREREQ([2.2])
LT_INIT
LT_LANG([C])

MESALINK_LIBRARY_VERSION=15:2:0
#                        | | |
#                 +------+ | +---+
#                 |        |     |
#                current:revision:age
#                 |        |     |
#                 |        |     +- increment if interfaces have been added
#                 |        |        set to zero if interfaces have been removed
#                 |        |        or changed
#                 |        +- increment if source code has changed
#                 |           set to zero if current is incremented
#                 +- increment if interfaces have been added, removed or changed
AC_SUBST([MESALINK_LIBRARY_VERSION])

AC_CHECK_HEADERS([netdb.h netinet/in.h string.h sys/socket.h unistd.h])
AC_CHECK_FUNCS([gethostbyname memset socket])
AC_CHECK_PROG(CARGO, [cargo], [yes], [no])
AS_IF(test x$CARGO = xno,
     AC_MSG_ERROR([cargo is required.  Please install the Rust toolchain from https://www.rust-lang.org/])
)
AC_CHECK_PROG(RUSTC, [rustc], [yes], [no])
AS_IF(test x$RUSTC = xno,
    AC_MSG_ERROR([rustc is required.  Please install the Rust toolchain from https://www.rust-lang.org/])
)

AX_COMPILER_VENDOR

if test x"$ax_cv_c_compiler_vendor" = x"gnu"
then
    LT_LINKER_ARGS="-Wl,--gc-sections"
fi

if test x"$ax_cv_c_compiler_vendor" = x"clang"
then
    LT_LINKER_ARGS="-Wl,-dead_strip"
fi
AC_SUBST([LT_LINKER_ARGS])

CARGO_RUSTC_ARGS="-- --emit asm"
OPTIMIZE_CFLAGS="-Os -fvisibility=hidden -ffunction-sections -fdata-sections"
DEBUG_CFLAGS="-g -ggdb -O0 -Wall"

AX_DEBUG

if test "$ax_enable_debug" = "yes"
then
    CFLAGS="$DEBUG_CFLAGS $CFLAGS"
    CARGO_TARGET_SUBDIR=debug
    CARGO_RELEASE_ARGS=
else
    CFLAGS="$OPTIMIZE_CFLAGS $CFLAGS"
    CARGO_TARGET_SUBDIR=release
    CARGO_RELEASE_ARGS=--release
fi

AM_CONDITIONAL([CARGO_DEBUG], [test "x$ax_enable_debug" = "xyes"])
AC_SUBST([CARGO_RELEASE_ARGS])

AC_ARG_ENABLE([rusthost],
    [AS_HELP_STRING([--enable-rusthost], [Set the Rust host for cross compilation (default: disabled)])],
    [ RUST_HOST=$enableval ],
    [ RUST_HOST= ]
    )

if test "x$RUST_HOST" = "x"
then
    CARGO_TARGET_ARGS=""
    CARGO_RUSTC_ARGS="$CARGO_RUSTC_ARGS"
    CARGO_TARGET_SUBDIR="$CARGO_TARGET_SUBDIR"
    CARGO_TARGET_SUBDIR_ENV_VAR=
else
    CARGO_TARGET_ARGS="--target $RUST_HOST"
    CARGO_RUSTC_ARGS="$CARGO_RUSTC_ARGS -C linker=$CC"
    CARGO_TARGET_SUBDIR="$RUST_HOST/$CARGO_TARGET_SUBDIR"
    CARGO_TARGET_SUBDIR_ENV_VAR="CARGO_TARGET_SUBDIR=$CARGO_TARGET_SUBDIR"
fi

RUSTC_VERSION=$( rustc --version | sed 's/[^0-9.]*\([0-9.]*\).*/\1/' )
AX_COMPARE_VERSION([$RUSTC_VERSION], [ge], [1.31.0])

IS_NIGHTLY=$( rustc --version | grep nightly )
RUST_IS_NIGHTLY="no"
if test "x$IS_NIGHTLY" != "x"
then
    RUST_IS_NIGHTLY="yes"
    CARGO_FEATURES=$CARGO_FEATURES" nightly"
fi

AC_SUBST([CARGO_TARGET_ARGS])
AC_SUBST([CARGO_RUSTC_ARGS])
AC_SUBST([CARGO_TARGET_SUBDIR])
AC_SUBST([CARGO_TARGET_SUBDIR_ENV_VAR])

AC_SUBST([CARGO_FEATURES], [--features ])
CARGO_FEATURES=$CARGO_FEATURES" \""

CONFIG_OPTIONS=""

AC_ARG_ENABLE([jemalloc],
    [AS_HELP_STRING([--enable-jemalloc], [Enable Jemalloc memory allocator (default: enabled)])],
    [ ENABLE_JEMALLOC=$enableval ],
    [ ENABLE_JEMALLOC=no ]
    )
if test "$ENABLE_JEMALLOC" = "yes"
then
    CARGO_FEATURES=$CARGO_FEATURES" jemalloc_allocator"
fi

AC_ARG_ENABLE([errorstrings],
    [AS_HELP_STRING([--enable-errorstrings], [Enable error string table (default: enabled)])],
    [ ENABLE_ERROR_STRINGS=$enableval ],
    [ ENABLE_ERROR_STRINGS=yes ]
    )
if test "$ENABLE_ERROR_STRINGS" = "yes"
then
    CARGO_FEATURES=$CARGO_FEATURES" error_strings"
    CONFIG_OPTIONS="$CONFIG_OPTIONS HAVE_ERROR_STRINGS"
else
    CONFIG_OPTIONS="$CONFIG_OPTIONS NO_ERROR_STRINGS"
fi

CARGO_FEATURES=$CARGO_FEATURES" verifier"
CARGO_FEATURES=$CARGO_FEATURES"\""

AC_ARG_ENABLE([examples],
    [AS_HELP_STRING([--enable-examples], [Enable examples (default: disabled)])],
    [ ENABLE_EXAMPLES=$enableval ],
    [ ENABLE_EXAMPLES=no ]
    )
AM_CONDITIONAL([BUILD_EXAMPLE_CLIENT], [test "x$ENABLE_EXAMPLES" = "xyes"])
AM_CONDITIONAL([BUILD_EXAMPLE_SERVER], [test "x$ENABLE_EXAMPLES" = "xyes"])

AX_CREATE_GENERIC_CONFIG

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([mesalink/options.h])
AC_CONFIG_FILES([mesalink/version.h])

AC_OUTPUT

echo "---"
echo "Running make clean ..."
make clean >/dev/null 2>&1

OPTION_FILE="mesalink/options.h"
rm -f $OPTION_FILE

echo "/* MesaLink options.h" > $OPTION_FILE
echo " * generated from configure options" >> $OPTION_FILE
echo " *" >> $OPTION_FILE
echo " * This file is part of MesaLink. " >> $OPTION_FILE
echo " *" >> $OPTION_FILE
echo " */" >> $OPTION_FILE

echo "" >> $OPTION_FILE
echo "#ifndef MESALINK_OPTIONS_H" >> $OPTION_FILE
echo "#define MESALINK_OPTIONS_H" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "#ifdef __cplusplus" >> $OPTION_FILE
echo "extern \"C\" {" >> $OPTION_FILE
echo "#endif" >> $OPTION_FILE
echo "" >> $OPTION_FILE

for option in $CONFIG_OPTIONS; do
    echo "#undef  $option" >> $OPTION_FILE
    echo "#define $option" >> $OPTION_FILE
    echo "" >> $OPTION_FILE
done

echo "" >> $OPTION_FILE
echo "#ifdef __cplusplus" >> $OPTION_FILE
echo "}" >> $OPTION_FILE
echo "#endif" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "#endif /* MESALINK_OPTIONS_H */" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo

echo "---"
echo "Configuration summary for $PACKAGE_NAME version $VERSION"
echo ""
echo "   * Installation prefix:        $prefix"
echo "   * Host:                       $host_cpu-$host_vendor-$host_os"
echo "   * Rust Host:                  $RUST_HOST"
echo "   * C Compiler:                 $CC"
echo "   * C Compiler vendor:          $ax_cv_c_compiler_vendor"
echo "   * C Flags:                    $CFLAGS"
echo "   * Debug enabled:              $ax_enable_debug"
echo "   * Rust version:               $RUSTC_VERSION"
echo "   * Nightly Rust:               $RUST_IS_NIGHTLY"
echo "   * Examples:                   $ENABLE_EXAMPLES"
echo
echo "   Features "
echo "   * Jemalloc:                   $ENABLE_JEMALLOC"
echo "   * Logging and error strings:  $ENABLE_ERROR_STRINGS"
echo ""
echo "---"
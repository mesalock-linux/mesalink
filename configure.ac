AC_INIT([mesalink], m4_esyscmd([grep version Cargo.toml | head -n1 | awk '{print $3}' | tr -d '"' | tr -d "\n"]), [jingyiming@baidu.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

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

LT_PREREQ([2.2])
LT_INIT
AC_DISABLE_SHARED
AC_ENABLE_STATIC
LT_LANG([C])

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
OPTIMIZE_CFLAGS="-Os -ffunction-sections -fdata-sections"
if test "$ax_cv_c_compiler_vendor" = "gnu"
then
    OPTIMIZE_CFLAGS="$OPTIMIZE_CFLAGS -Wl,--gc-sections"
fi
if test "$ax_cv_c_compiler_vendor" = "clang"
then
    OPTIMIZE_CFLAGS="$OPTIMIZE_CFLAGS -Wl,-dead_strip"
fi
DEBUG_CFLAGS="-g -ggdb -O0 -Wall"

AX_DEBUG

AC_ARG_VAR([RUST_TARGET], [Set the Rust target for cross-compilation])

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

AC_ARG_VAR([RUST_TARGET], [Set the Rust target for cross-compilation])

if test "x$RUST_TARGET" = "x"
then
    CARGO_TARGET_ARGS=""
    CARGO_TARGET_SUBDIR="$CARGO_TARGET_SUBDIR"
    CARGO_TARGET_SUBDIR_ENV_VAR=
else 
    CARGO_TARGET_ARGS="--target $RUST_TARGET"
    CARGO_TARGET_SUBDIR="$CARGO_TARGET_SUBDIR/$RUST_TARGET"
    CARGO_TARGET_SUBDIR_ENV_VAR="CARGO_TARGET_SUBDIR=$CARGO_TARGET_SUBDIR"
fi

AC_SUBST([CARGO_TARGET_ARGS])
AC_SUBST([CARGO_TARGET_SUBDIR])
AC_SUBST([CARGO_TARGET_SUBDIR_ENV_VAR])

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

AC_ARG_ENABLE([tls13],
    [AS_HELP_STRING([--enable-tls13], [Enable TLS 1.3 draft (default: enabled)])],
    [ ENABLE_TLS13=$enableval ],
    [ ENABLE_TLS13=yes ]
    )
if test "$ENABLE_TLS13" = "yes"
then
    CARGO_FEATURES=$CARGO_FEATURES" tls13"
fi

AC_ARG_ENABLE([x25519],
    [AS_HELP_STRING([--enable-x25519], [Enable Curve25519 for key exchange (default: enabled)])],
    [ ENABLE_X25519=$enableval ],
    [ ENABLE_X25519=yes ]
    )
if test "$ENABLE_X25519" = "yes"
then
    CARGO_FEATURES=$CARGO_FEATURES" x25519"
fi

AC_ARG_ENABLE([ecdh],
    [AS_HELP_STRING([--enable-ecdh], [Enable curve secp256r1 and secp384r1 for key exchange (default: enabled)])],
    [ ENABLE_ECDH=$enableval ],
    [ ENABLE_ECDH=yes ]
    )
if test "$ENABLE_ECDH" = "yes"
then
    CARGO_FEATURES=$CARGO_FEATURES" ecdh"
fi

AC_ARG_ENABLE([ecdsa],
    [AS_HELP_STRING([--enable-ecdsa], [Enable curve secp256r1 and secp384r1 for signature verification (default: enabled)])],
    [ ENABLE_ECDSA=$enableval ],
    [ ENABLE_ECDSA=yes ]
    )
if test "$ENABLE_ECDSA" = "yes"
then
    CARGO_FEATURES=$CARGO_FEATURES" ecdsa"
fi

CARGO_FEATURES=$CARGO_FEATURES"\""

AX_CREATE_GENERIC_CONFIG

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
echo "   * Rust Target:                $RUST_TARGET"
echo "   * C Compiler:                 $CC"
echo "   * C Compiler vendor:          $ax_cv_c_compiler_vendor"
echo "   * C Flags:                    $CFLAGS"
echo "   * Debug enabled:              $ax_enable_debug"
echo
echo "   Features "
echo "   * Logging and error strings:  $ENABLE_ERROR_STRINGS"
echo "   * AES-GCM:                    $ENABLE_AESGCM"
echo "   * Chacha20-Poly1305:          $ENABLE_CHACHAPOLY"
echo "   * TLS 1.3 (draft):            $ENABLE_TLS13"
echo "   * X25519 key exchange:        $ENABLE_X25519"
echo "   * EC key exchange:            $ENABLE_ECDH"
echo "   * RSA signature verification: yes"
echo "   * EC signature verification:  $ENABLE_ECDSA"
echo ""
echo "---"

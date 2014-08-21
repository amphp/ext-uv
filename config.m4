PHP_ARG_WITH(uv, Whether to include "uv" support,
[ --with-uv[=DIR]        Include "uv" support])

PHP_ARG_ENABLE(httpparser, Whether to enable the "httpparser" module,
    [ --enable-httpparser     Enable "httpparser" module support], no, no)

PHP_ARG_ENABLE(uv-debug, for uv debug support,
    [ --enable-uv-debug       Enable enable uv debug support], no, no)

PHP_ARG_ENABLE(dtrace, Whether to enable the "dtrace" debug,
    [ --enable-dtrace         Enable "dtrace" support], no, no)


if test -z "$PHP_DEBUG"; then
    AC_ARG_ENABLE(debug,
    [  --enable-debug          compile with debugging symbols],[
        PHP_DEBUG=$enableval
    ],[    PHP_DEBUG=no
    ])
fi

if test "$PHP_UV_DEBUG" != "no"; then
    CFLAGS="$CFLAGS -Wall -g -ggdb -O0 -DPHP_UV_DEBUG=1"
    AC_DEFINE(PHP_UV_DEBUG, 1, [Enable uv debug support])
fi

if test "$PHP_DTRACE" != "no"; then
    dnl TODO: we should move this line to Makefile.frag or somewhere.
    case $host in
        *darwin*)
             dtrace -h -s phpuv_dtrace.d
             UV_SHARED_DEPENDENCIES=phpuv_dtrace.h
             PHP_ADD_LIBRARY(dtrace, UV_SHARED_LIBADD)
             AC_DEFINE(PHP_UV_DTRACE, 1, [Enable uv dtrace support])
             PHP_SUBST(UV_SHARED_DEPENDENCIES)
             PHP_ADD_MAKEFILE_FRAGMENT
        ;;
        *linux*)
             echo "dtrace does not support this machine. currently OSX only"
    esac
fi

if test $PHP_UV != "no"; then
    SOURCES=""

    if test $PHP_HTTPPARSER != "no"; then
        SOURCES=" uv_http_parser.c http-parser/http_parser.c"
        AC_DEFINE([ENABLE_HTTPPARSER], [1], [ Enable http parser])
    fi

    PHP_NEW_EXTENSION(uv, php_uv.c uv.c $SOURCES, $ext_shared)

    if test $PHP_HTTPPARSER != "no"; then
        PHP_ADD_INCLUDE([$ext_srcdir/http-parser])
    fi

    SEARCH_PATH="/usr/local /usr"
    SEARCH_FOR="/include/uv.h"
    if test -r $PHP_UV/$SEARCH_FOR; then # path given as parameter
       UV_DIR=$PHP_UV
    else # search default path list
       AC_MSG_CHECKING([for libuv files in default path])
       for i in $SEARCH_PATH ; do
           if test -r $i/$SEARCH_FOR; then
             UV_DIR=$i
             AC_MSG_RESULT(found in $i)
           fi
       done
    fi

    PHP_ADD_INCLUDE($UV_DIR/include)

    PHP_CHECK_LIBRARY(uv, uv_version,
    [
      PHP_ADD_LIBRARY_WITH_PATH(uv, $UV_DIR/lib, UV_SHARED_LIBADD)
      AC_DEFINE(HAVE_UVLIB,1,[ ])
    ],[
      AC_MSG_ERROR([wrong uv library version or library not found])
    ],[
      -L$UV_DIR/lib -lm
    ])

    PHP_SUBST(UV_SHARED_LIBADD)
fi

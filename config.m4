PHP_ARG_ENABLE(uv, Whether to enable the "uv" extension,
[  --enable-uv     Enable "uv" extension support])

PHP_ARG_ENABLE(httpparser, Whether to enable the "httpparser" module,
    [ --enable-httpparser     Enable "httpparser" module support])

PHP_ARG_ENABLE(uv-debug, for uv debug support,
    [ --enable-uv-debug       Enable enable uv deubg support], no, no)

PHP_ARG_ENABLE(dtrace, Whether to enable the "dtrace" debug,
    [ --enable-dtrace     Enable "dtrace" support])


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

if test "$PHP_UV_DTRACE" != "no"; then
  UV_SHARED_DEPENDENCIES=dtrace-fixup
  UV_SHARED_LIBADD="phpuv.o -Wl,-M$srcdir/kludge.map"

  PHP_ADD_LIBRARY(dtrace, UV_SHARED_LIBADD)
  PHP_SUBST(UV_SHARED_DEPENDENCIES)
fi

if test $PHP_UV != "no"; then
    SOURCES=""

    if test $PHP_HTTPPARSER != "no"; then
        SOURCES=" http-parser/http_parser.c"
        AC_DEFINE([ENABLE_HTTPPARSER], [1], [ Enable http parser])
    fi

    PHP_NEW_EXTENSION(uv, php_uv.c uv.c $SOURCES, $ext_shared)

    if test $PHP_HTTPPARSER != "no"; then
        PHP_ADD_INCLUDE([$ext_srcdir/http-parser])
    fi
    PHP_ADD_INCLUDE([$ext_srcdir/libuv/include])
 
    CFLAGS=" $CFLAGS -Wunused-variable -Wpointer-sign -Wimplicit-function-declaration -Wl,libuv/uv.a"

    case $host in
        *darwin*)
            dnl these macro does not work. why?
            dnl
            dnl PHP_ADD_FRAMEWORK(CoreServices)
            dnl PHP_ADD_FRAMEWORK(Carbon)

            CFLAGS="$CFLAGS -framework CoreServices -framework Carbon"
        ;;
        *linux*)
    esac

    PHP_SUBST(UV_SHARED_LIBADD)
    PHP_SUBST([CFLAGS])
    PHP_ADD_MAKEFILE_FRAGMENT
fi

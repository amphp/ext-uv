PHP_ARG_ENABLE(uv, Whether to enable the "uv" extension,
[  --enable-uv     Enable "uv" extension support])

if test -z "$PHP_DEBUG"; then
    AC_ARG_ENABLE(debug,
    [  --enable-debug          compile with debugging symbols],[
        PHP_DEBUG=$enableval
    ],[    PHP_DEBUG=no
    ])
fi

if test $PHP_UV != "no"; then
    PHP_NEW_EXTENSION(uv, php_uv.c uv.c, $ext_shared)

    PHP_ADD_INCLUDE([$ext_srcdir/libuv/include])
 
    CFLAGS=" -g -O0 -Wunused-variable -Wpointer-sign -Wimplicit-function-declaration -Wl,libuv/uv.a"

    dnl if test $PHP_DEBUG != "no"; then
    dnl    CFLAGS="$CFLAGS -DPHP_UV_DEBUG=1"
    dnl fi

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
fi

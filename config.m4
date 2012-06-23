PHP_ARG_ENABLE(uv, Whether to enable the "uv" extension,
    [ --enable-uv     Enable "uv" extension support])

if test $PHP_UV != "no"; then
    PHP_NEW_EXTENSION(uv, php_uv.c uv.c, $ext_shared)

    PHP_ADD_INCLUDE([$ext_srcdir/libuv/include])

    PHP_SUBST(UV_SHARED_LIBADD)
    CFLAGS=" -g -O0 -Wunused-variable -Wpointer-sign -Wimplicit-function-declaration -Wl,libuv/uv.a -framework Carbon -framework CoreServices"
    PHP_SUBST([CFLAGS])
fi

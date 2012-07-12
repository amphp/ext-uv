dtrace-fixup:
	if test -f $(builddir)/.libs/phpuv.o ; then \
		dtrace -h -C -s $(srcdir)/phpuv.d $(builddir)/.libs/phpuv.o ; \
	else \
		dtrace -h -C -s  $(srcdir)/phpuv.d phpuv.lo ; \
	fi

$(srcdir)/libuv/uv.a:
	$(MAKE) -C $(srcdir)/libuv
	cp $(srcdir)/libuv/uv.a $(srcdir)/libuv/libuv.a

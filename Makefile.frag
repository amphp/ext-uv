phpuv_dtrace.h:
	dtrace -h -s  $(srcdir)/phpuv_dtrace.d; \

$(srcdir)/libuv/uv.a:
	$(MAKE) -C $(srcdir)/libuv
	cp $(srcdir)/libuv/uv.a $(srcdir)/libuv/libuv.a

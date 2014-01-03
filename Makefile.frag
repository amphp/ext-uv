phpuv_dtrace.h:
	dtrace -h -s  $(srcdir)/phpuv_dtrace.d; \

$(srcdir)/libuv/libuv.a:
	$(MAKE) -C $(srcdir)/libuv

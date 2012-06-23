# TODO

* resource ref counting.

# Not tested

* UV_EXTERN int uv_process_kill(uv_process_t*, int signum);
* UV_EXTERN uv_err_t uv_set_process_title(const char* title);


# functions

* UV_EXTERN int uv_read2_start(uv_stream_t*, uv_alloc_cb alloc_cb,uv_read2_cb read_cb);
* UV_EXTERN int uv_write2(uv_write_t* req, uv_stream_t* handle, uv_buf_t bufs[],int bufcnt, uv_stream_t* send_handle, uv_write_cb cb);
* UV_EXTERN int uv_tcp_simultaneous_accepts(uv_tcp_t* handle, int enable);
* UV_EXTERN int uv_tcp_bind6(uv_tcp_t* handle, struct sockaddr_in6);
* UV_EXTERN int uv_tcp_getsockname(uv_tcp_t* handle, struct sockaddr* name,int* namelen);
* UV_EXTERN int uv_tcp_getpeername(uv_tcp_t* handle, struct sockaddr* name,int* namelen);
* UV_EXTERN int uv_tcp_connect6(uv_connect_t* req, uv_tcp_t* handle,struct sockaddr_in6 address, uv_connect_cb cb);
* UV_EXTERN int uv_udp_bind6(uv_udp_t* handle, struct sockaddr_in6 addr,unsigned flags);
* UV_EXTERN int uv_udp_getsockname(uv_udp_t* handle, struct sockaddr* name,int* namelen);
* UV_EXTERN int uv_udp_set_membership(uv_udp_t* handle,const char* multicast_addr, const char* interface_addr,uv_membership membership);

* UV_EXTERN void uv_ares_destroy(uv_loop_t*, ares_channel channel);

* UV_EXTERN int uv_getaddrinfo(uv_loop_t*, uv_getaddrinfo_t* handle,uv_getaddrinfo_cb getaddrinfo_cb, const char* node, const char* service,const struct addrinfo* hints);
* UV_EXTERN void uv_freeaddrinfo(struct addrinfo* ai);


* UV_EXTERN int uv_queue_work(uv_loop_t* loop, uv_work_t* req,uv_work_cb work_cb, uv_after_work_cb after_work_cb);
* UV_EXTERN char** uv_setup_args(int argc, char** argv);
* UV_EXTERN uv_err_t uv_resident_set_memory(size_t* rss);

* UV_EXTERN struct sockaddr_in6 uv_ip6_addr(const char* ip, int port);
* UV_EXTERN int uv_ip4_name(struct sockaddr_in* src, char* dst, size_t size);
* UV_EXTERN int uv_ip6_name(struct sockaddr_in6* src, char* dst, size_t size);

* UV_EXTERN void uv_once(uv_once_t* guard, void (*callback)(void));
* UV_EXTERN int uv_thread_create(uv_thread_t *tid,void (*entry)(void *arg), void *arg);
* UV_EXTERN int uv_thread_join(uv_thread_t *tid);

# Not support

* UV_EXTERN uv_handle_type uv_guess_handle(uv_file file);

* UV_EXTERN uv_buf_t uv_buf_init(char* base, size_t len);
* UV_EXTERN size_t uv_strlcpy(char* dst, const char* src, size_t size);
* UV_EXTERN size_t uv_strlcat(char* dst, const char* src, size_t size);

* UV_EXTERN uv_err_t uv_dlopen(const char* filename, uv_lib_t* library);
* UV_EXTERN uv_err_t uv_dlclose(uv_lib_t library);
* UV_EXTERN uv_err_t uv_dlsym(uv_lib_t library, const char* name, void** ptr);
* UV_EXTERN const char *uv_dlerror(uv_lib_t library);
* UV_EXTERN void uv_dlerror_free(uv_lib_t library, const char *msg);

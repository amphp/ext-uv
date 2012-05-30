# TODO

* resource ref counting.

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
* UV_EXTERN int uv_udp_set_membership(uv_udp_t* handle,const char* multicast_addr, const char* interface_addr,uv_membership membership);

* UV_EXTERN int uv_tty_init(uv_loop_t*, uv_tty_t*, uv_file fd, int readable);
* UV_EXTERN int uv_tty_set_mode(uv_tty_t*, int mode);
* UV_EXTERN void uv_tty_reset_mode(void);
* UV_EXTERN int uv_tty_get_winsize(uv_tty_t*, int* width, int* height);
* UV_EXTERN uv_handle_type uv_guess_handle(uv_file file);
* UV_EXTERN int uv_pipe_init(uv_loop_t*, uv_pipe_t* handle, int ipc);

* UV_EXTERN void uv_pipe_open(uv_pipe_t*, uv_file file);
* UV_EXTERN int uv_pipe_bind(uv_pipe_t* handle, const char* name);
* UV_EXTERN void uv_pipe_connect(uv_connect_t* req, uv_pipe_t* handle,const char* name, uv_connect_cb cb);
* UV_EXTERN void uv_pipe_pending_instances(uv_pipe_t* handle, int count);

* UV_EXTERN int uv_prepare_init(uv_loop_t*, uv_prepare_t* prepare);
* UV_EXTERN int uv_prepare_start(uv_prepare_t* prepare, uv_prepare_cb cb);
* UV_EXTERN int uv_prepare_stop(uv_prepare_t* prepare);

* UV_EXTERN int uv_check_init(uv_loop_t*, uv_check_t* check);
* UV_EXTERN int uv_check_start(uv_check_t* check, uv_check_cb cb);
* UV_EXTERN int uv_check_stop(uv_check_t* check);

* UV_EXTERN int uv_async_init(uv_loop_t*, uv_async_t* async,uv_async_cb async_cb);
* UV_EXTERN int uv_async_send(uv_async_t* async);

* UV_EXTERN  int uv_ares_init_options(uv_loop_t*,ares_channel *channelptr, struct ares_options *options, int optmask);
* UV_EXTERN void uv_ares_destroy(uv_loop_t*, ares_channel channel);

* UV_EXTERN int uv_getaddrinfo(uv_loop_t*, uv_getaddrinfo_t* handle,uv_getaddrinfo_cb getaddrinfo_cb, const char* node, const char* service,const struct addrinfo* hints);
* UV_EXTERN void uv_freeaddrinfo(struct addrinfo* ai);

* UV_EXTERN int uv_spawn(uv_loop_t*, uv_process_t*,uv_process_options_t options);
* UV_EXTERN int uv_process_kill(uv_process_t*, int signum);
* UV_EXTERN uv_err_t uv_kill(int pid, int signum);

* UV_EXTERN int uv_queue_work(uv_loop_t* loop, uv_work_t* req,uv_work_cb work_cb, uv_after_work_cb after_work_cb);
* UV_EXTERN char** uv_setup_args(int argc, char** argv);
* UV_EXTERN uv_err_t uv_get_process_title(char* buffer, size_t size);
* UV_EXTERN uv_err_t uv_set_process_title(const char* title);
* UV_EXTERN uv_err_t uv_resident_set_memory(size_t* rss);
* UV_EXTERN uv_err_t uv_uptime(double* uptime);

* UV_EXTERN uv_err_t uv_cpu_info(uv_cpu_info_t** cpu_infos, int* count);
* UV_EXTERN void uv_free_cpu_info(uv_cpu_info_t* cpu_infos, int count);

* UV_EXTERN uv_err_t uv_interface_addresses(uv_interface_address_t** addresses,int* count);
* UV_EXTERN void uv_free_interface_addresses(uv_interface_address_t* addresses,int count);

* UV_EXTERN void uv_fs_req_cleanup(uv_fs_t* req);
* UV_EXTERN int uv_fs_close(uv_loop_t* loop, uv_fs_t* req, uv_file file,uv_fs_cb cb);
* UV_EXTERN int uv_fs_open(uv_loop_t* loop, uv_fs_t* req, const char* path,int flags, int mode, uv_fs_cb cb);
* UV_EXTERN int uv_fs_read(uv_loop_t* loop, uv_fs_t* req, uv_file file,void* buf, size_t length, off_t offset, uv_fs_cb cb);
* UV_EXTERN int uv_fs_unlink(uv_loop_t* loop, uv_fs_t* req, const char* path,uv_fs_cb cb);
* UV_EXTERN int uv_fs_write(uv_loop_t* loop, uv_fs_t* req, uv_file file,void* buf, size_t length, off_t offset, uv_fs_cb cb);
* UV_EXTERN int uv_fs_mkdir(uv_loop_t* loop, uv_fs_t* req, const char* path,int mode, uv_fs_cb cb);
* UV_EXTERN int uv_fs_rmdir(uv_loop_t* loop, uv_fs_t* req, const char* path,uv_fs_cb cb);
* UV_EXTERN int uv_fs_readdir(uv_loop_t* loop, uv_fs_t* req,const char* path, int flags, uv_fs_cb cb);
* UV_EXTERN int uv_fs_stat(uv_loop_t* loop, uv_fs_t* req, const char* path,uv_fs_cb cb);
* UV_EXTERN int uv_fs_fstat(uv_loop_t* loop, uv_fs_t* req, uv_file file,uv_fs_cb cb);
* UV_EXTERN int uv_fs_rename(uv_loop_t* loop, uv_fs_t* req, const char* path,const char* new_path, uv_fs_cb cb);
* UV_EXTERN int uv_fs_fsync(uv_loop_t* loop, uv_fs_t* req, uv_file file,uv_fs_cb cb);
* UV_EXTERN int uv_fs_fdatasync(uv_loop_t* loop, uv_fs_t* req, uv_file file,uv_fs_cb cb);
* UV_EXTERN int uv_fs_ftruncate(uv_loop_t* loop, uv_fs_t* req, uv_file file,off_t offset, uv_fs_cb cb);
* UV_EXTERN int uv_fs_sendfile(uv_loop_t* loop, uv_fs_t* req, uv_file out_fd,uv_file in_fd, off_t in_offset, size_t length, uv_fs_cb cb);
* UV_EXTERN int uv_fs_chmod(uv_loop_t* loop, uv_fs_t* req, const char* path,int mode, uv_fs_cb cb);
* UV_EXTERN int uv_fs_utime(uv_loop_t* loop, uv_fs_t* req, const char* path,double atime, double mtime, uv_fs_cb cb);
* UV_EXTERN int uv_fs_futime(uv_loop_t* loop, uv_fs_t* req, uv_file file,double atime, double mtime, uv_fs_cb cb);
* UV_EXTERN int uv_fs_lstat(uv_loop_t* loop, uv_fs_t* req, const char* path,uv_fs_cb cb);
* UV_EXTERN int uv_fs_link(uv_loop_t* loop, uv_fs_t* req, const char* path,const char* new_path, uv_fs_cb cb);
* UV_EXTERN int uv_fs_symlink(uv_loop_t* loop, uv_fs_t* req, const char* path,const char* new_path, int flags, uv_fs_cb cb);
* UV_EXTERN int uv_fs_readlink(uv_loop_t* loop, uv_fs_t* req, const char* path,uv_fs_cb cb);
* UV_EXTERN int uv_fs_fchmod(uv_loop_t* loop, uv_fs_t* req, uv_file file,int mode, uv_fs_cb cb);
* UV_EXTERN int uv_fs_chown(uv_loop_t* loop, uv_fs_t* req, const char* path,int uid, int gid, uv_fs_cb cb);
* UV_EXTERN int uv_fs_fchown(uv_loop_t* loop, uv_fs_t* req, uv_file file,int uid, int gid, uv_fs_cb cb);

* UV_EXTERN void uv_loadavg(double avg[3]);

* UV_EXTERN int uv_fs_event_init(uv_loop_t* loop, uv_fs_event_t* handle,const char* filename, uv_fs_event_cb cb, int flags);

* UV_EXTERN struct sockaddr_in6 uv_ip6_addr(const char* ip, int port);
* UV_EXTERN int uv_ip4_name(struct sockaddr_in* src, char* dst, size_t size);
* UV_EXTERN int uv_ip6_name(struct sockaddr_in6* src, char* dst, size_t size);

* UV_EXTERN int uv_exepath(char* buffer, size_t* size);
* UV_EXTERN uv_err_t uv_cwd(char* buffer, size_t size);
* UV_EXTERN uv_err_t uv_chdir(const char* dir);
* UV_EXTERN uint64_t uv_get_free_memory(void);
* UV_EXTERN uint64_t uv_get_total_memory(void);
* UV_EXTERN extern uint64_t uv_hrtime(void);

* UV_EXTERN int uv_mutex_init(uv_mutex_t* handle);
* UV_EXTERN void uv_mutex_destroy(uv_mutex_t* handle);
* UV_EXTERN void uv_mutex_lock(uv_mutex_t* handle);
* UV_EXTERN int uv_mutex_trylock(uv_mutex_t* handle);
* UV_EXTERN void uv_mutex_unlock(uv_mutex_t* handle);

* UV_EXTERN int uv_rwlock_init(uv_rwlock_t* rwlock);
* UV_EXTERN void uv_rwlock_destroy(uv_rwlock_t* rwlock);
* UV_EXTERN void uv_rwlock_rdlock(uv_rwlock_t* rwlock);
* UV_EXTERN int uv_rwlock_tryrdlock(uv_rwlock_t* rwlock);
* UV_EXTERN void uv_rwlock_rdunlock(uv_rwlock_t* rwlock);
* UV_EXTERN void uv_rwlock_wrlock(uv_rwlock_t* rwlock);
* UV_EXTERN int uv_rwlock_trywrlock(uv_rwlock_t* rwlock);
* UV_EXTERN void uv_rwlock_wrunlock(uv_rwlock_t* rwlock);

* UV_EXTERN void uv_once(uv_once_t* guard, void (*callback)(void));
* UV_EXTERN int uv_thread_create(uv_thread_t *tid,void (*entry)(void *arg), void *arg);
* UV_EXTERN int uv_thread_join(uv_thread_t *tid);


# Not support

* UV_EXTERN uv_buf_t uv_buf_init(char* base, size_t len);
* UV_EXTERN size_t uv_strlcpy(char* dst, const char* src, size_t size);
* UV_EXTERN size_t uv_strlcat(char* dst, const char* src, size_t size);

* UV_EXTERN uv_err_t uv_dlopen(const char* filename, uv_lib_t* library);
* UV_EXTERN uv_err_t uv_dlclose(uv_lib_t library);
* UV_EXTERN uv_err_t uv_dlsym(uv_lib_t library, const char* name, void** ptr);
* UV_EXTERN const char *uv_dlerror(uv_lib_t library);
* UV_EXTERN void uv_dlerror_free(uv_lib_t library, const char *msg);

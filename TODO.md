# TODO

* implement all test cases.
* improve source code.(avoids copy and paste)
* more error handling
* buffer allocator
* documents

# Known Issues

* something wrong on OSX box. (corrupted queue, fs event...)
* windows support (currently, this can build. but not fully tested).

# functions (not implemented or not tested)

* UV_EXTERN int uv_write2(uv_write_t* req, uv_stream_t* handle, uv_buf_t bufs[],int bufcnt, uv_stream_t* send_handle, uv_write_cb cb);
* UV_EXTERN int uv_queue_work(uv_loop_t* loop, uv_work_t* req, uv_work_cb work_cb, uv_after_work_cb after_work_cb);
* UV_EXTERN int uv_is_closing(const uv_handle_t* handle);

# Not support

* UV_EXTERN void uv_once(uv_once_t* guard, void (*callback)(void));
we don't support thread. so this function does not need.

* UV_EXTERN uv_buf_t uv_buf_init(char* base, size_t len);
* UV_EXTERN size_t uv_strlcpy(char* dst, const char* src, size_t size);
* UV_EXTERN size_t uv_strlcat(char* dst, const char* src, size_t size);

* UV_EXTERN uv_err_t uv_dlopen(const char* filename, uv_lib_t* library);
* UV_EXTERN uv_err_t uv_dlclose(uv_lib_t library);
* UV_EXTERN uv_err_t uv_dlsym(uv_lib_t library, const char* name, void** ptr);
* UV_EXTERN const char *uv_dlerror(uv_lib_t library);
* UV_EXTERN void uv_dlerror_free(uv_lib_t library, const char *msg);

* UV_EXTERN char** uv_setup_args(int argc, char** argv);
* UV_EXTERN uv_err_t uv_get_process_title(char* buffer, size_t size);
* UV_EXTERN uv_err_t uv_set_process_title(const char* title);

* UV_EXTERN int uv_thread_create(uv_thread_t *tid,void (*entry)(void *arg), void *arg);
* UV_EXTERN int uv_thread_join(uv_thread_t *tid);

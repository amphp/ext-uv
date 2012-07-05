/*
   +----------------------------------------------------------------------+
   | PHP Version 5                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2012 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Shuhei Tanuma <chobieeee@php.net>                          |
   +----------------------------------------------------------------------+
 */


#include "php_uv.h"
#include "ext/standard/info.h"

#ifndef PHP_UV_DEBUG
#define PHP_UV_DEBUG 0
#endif

#define PHP_UV_INIT_UV(uv, uv_type) \
	uv = (php_uv_t *)emalloc(sizeof(php_uv_t)); \
	if (!uv) { \
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "emalloc failed"); \
		return; \
	} else { \
		uv->type = uv_type; \
		PHP_UV_INIT_ZVALS(uv) \
		TSRMLS_SET_CTX(uv->thread_ctx); \
		uv->resource_id = PHP_UV_LIST_INSERT(uv, uv_resource_handle); \
	}

#define PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop) \
	{ \
		if (zloop != NULL) { \
			ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle); \
		} else { \
			loop = uv_default_loop(); \
		}  \
	}

#define PHP_UV_FS_ASYNC(loop, func,  ...) \
	error = uv_fs_##func(loop, (uv_fs_t*)&uv->uv.fs, __VA_ARGS__, php_uv_fs_cb); \
	if (error) { \
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_##func failed"); \
		return; \
	}

#define PHP_UV_INIT_ZVALS(uv) \
	{ \
		uv->address     = NULL; \
		uv->listen_cb   = NULL; \
		uv->read_cb     = NULL; \
		uv->read2_cb     = NULL; \
		uv->write_cb    = NULL; \
		uv->close_cb    = NULL; \
		uv->shutdown_cb = NULL; \
		uv->timer_cb    = NULL; \
		uv->idle_cb     = NULL; \
		uv->connect_cb  = NULL; \
		uv->getaddr_cb  = NULL; \
		uv->udp_recv_cb  = NULL; \
		uv->udp_send_cb  = NULL; \
		uv->pipe_connect_cb = NULL; \
		uv->proc_close_cb = NULL; \
		uv->prepare_cb = NULL; \
		uv->check_cb = NULL; \
		uv->work_cb = NULL; \
		uv->async_cb = NULL; \
		uv->after_work_cb = NULL; \
		uv->fs_cb = NULL; \
		uv->fs_event_cb = NULL; \
	}

#if PHP_UV_DEBUG>=1
#define PHP_UV_DEBUG_PRINT(format, ...) fprintf(stderr, format, ## __VA_ARGS__)
#else
#define PHP_UV_DEBUG_PRINT(format, ...)
#endif

#if PHP_UV_DEBUG>=1
#define PHP_UV_DEBUG_RESOURCE_REFCOUNT(name, resource_id) \
	{ \
		zend_rsrc_list_entry *le; \
		if (zend_hash_index_find(&EG(regular_list), resource_id, (void **) &le)==SUCCESS) { \
			printf("# %s del(%d): %d->%d\n", #name, resource_id, le->refcount, le->refcount-1); \
		} else { \
			printf("# can't find (%s)", #name); \
		} \
	} 
#else
#define PHP_UV_DEBUG_RESOURCE_REFCOUNT(name, resource_id)
#endif


extern void php_uv_init(TSRMLS_D);
extern zend_class_entry *uv_class_entry;

typedef struct {
	uv_write_t req;
	uv_buf_t buf;
} write_req_t;

typedef struct {
	uv_udp_send_t req;
	uv_buf_t buf;
} send_req_t;

/* static variables */

static uv_loop_t *_php_uv_default_loop;

/* resources */

static int uv_resource_handle;

static int uv_ares_handle;

static int uv_loop_handle;

static int uv_sockaddr_handle;

static int uv_lock_handle;

static int uv_httpparser_handle;

static int uv_ares_initialized;

/* TODO: fix this */
static char uv_fs_read_buf[8192];

/* declarations */

void php_uv_init(TSRMLS_D);

static inline uv_stream_t* php_uv_get_current_stream(php_uv_t *uv);

/**
 * execute callback
 *
 * @param zval** retval_ptr non-initialized pointer. this will be allocate from zend_call_function
 * @param zval* callback callable object
 * @param zval** params parameters.
 * @param int param_count
 * @return int (maybe..)
 */
static int php_uv_do_callback(zval **retval_ptr, zval *callback, zval ***params, int param_count TSRMLS_DC);

static void php_uv_close_cb(uv_handle_t *handle);

void static destruct_uv(zend_rsrc_list_entry *rsrc TSRMLS_DC);

static void php_uv_tcp_connect_cb(uv_connect_t *conn_req, int status);

static void php_uv_write_cb(uv_write_t* req, int status);

static void php_uv_listen_cb(uv_stream_t* server, int status);

static void php_uv_close_cb2(uv_handle_t *handle);

static void php_uv_shutdown_cb(uv_shutdown_t* req, int status);

static void php_uv_read_cb(uv_stream_t* handle, ssize_t nread, uv_buf_t buf);

static void php_uv_read2_cb(uv_pipe_t* handle, ssize_t nread, uv_buf_t buf, uv_handle_type pending);

static uv_buf_t php_uv_read_alloc(uv_handle_t* handle, size_t suggested_size);

static void php_uv_close_cb(uv_handle_t *handle);

static void php_uv_timer_cb(uv_timer_t *handle, int status);

static void php_uv_idle_cb(uv_timer_t *handle, int status);

/* util */

static void php_uv_ares_destroy()
{
	if (uv_ares_initialized == 1) {
		ares_library_cleanup();
	}
}

static void php_uv_ares_init(TSRMLS_D)
{
	int rc = 0;

	if (uv_ares_initialized == 0) {
		rc = ares_library_init(ARES_LIB_INIT_ALL);
		if (rc != 0) {
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "failed to initialize ares library");
			return;
		}
		uv_ares_initialized = 1;
	}
}

static zval *php_uv_address_to_zval(const struct sockaddr *addr)
{
	zval *tmp;
	char ip[INET6_ADDRSTRLEN];
	const struct sockaddr_in *a4;
	const struct sockaddr_in6 *a6;
	int port;
	
	MAKE_STD_ZVAL(tmp);
	array_init(tmp);
	
	switch (addr->sa_family) {
		case AF_INET6:
		{
			a6 = (const struct sockaddr_in6 *)addr;
			uv_inet_ntop(AF_INET, &a6->sin6_addr, ip, sizeof ip);
			port = ntohs(a6->sin6_port);
			
			add_assoc_string_ex(tmp, "address",sizeof("address"), ip, 1);
			add_assoc_long_ex(tmp, "port", sizeof("port"), port);
			add_assoc_string_ex(tmp, "family",sizeof("address"), "IPv6", 1);
			break;
		}
		case AF_INET:
		{
			a4 = (const struct sockaddr_in *)addr;
			uv_inet_ntop(AF_INET, &a4->sin_addr, ip, sizeof ip);
			port = ntohs(a4->sin_port);
			
			add_assoc_string_ex(tmp, "address",sizeof("address"), ip, 1);
			add_assoc_long_ex(tmp, "port", sizeof("port"), port);
			add_assoc_string_ex(tmp, "family",sizeof("address"), "IPv4", 1);
			break;
		}
		default:
		break;
	}
	
	return tmp;
}

static zval *php_uv_make_stat(const uv_statbuf_t *s)
{
	zval *tmp;
	MAKE_STD_ZVAL(tmp);
	array_init(tmp);
	
	add_assoc_long_ex(tmp, "dev", sizeof("dev"), s->st_dev);
	add_assoc_long_ex(tmp, "ino", sizeof("ino"), s->st_ino);
	add_assoc_long_ex(tmp, "mode", sizeof("mode"), s->st_mode);
	add_assoc_long_ex(tmp, "nlink", sizeof("nlink"), s->st_nlink);
	add_assoc_long_ex(tmp, "uid", sizeof("uid"), s->st_uid);
	add_assoc_long_ex(tmp, "gid", sizeof("gid"), s->st_gid);
	add_assoc_long_ex(tmp, "rdev", sizeof("rdev"), s->st_rdev);
	add_assoc_long_ex(tmp, "size", sizeof("size"), s->st_size);

#ifndef PHP_WIN32
	add_assoc_long_ex(tmp, "blksize", sizeof("blksize"), s->st_blksize);
	add_assoc_long_ex(tmp, "blocks", sizeof("blocks"), s->st_blocks);
#endif

	add_assoc_long_ex(tmp, "atime", sizeof("atime"), s->st_atime);
	add_assoc_long_ex(tmp, "mtime", sizeof("mtime"), s->st_mtime);
	add_assoc_long_ex(tmp, "ctime", sizeof("ctime"), s->st_ctime);

	
	return tmp;
}

/* destructor */

void static destruct_uv_lock(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	php_uv_lock_t *lock = (php_uv_lock_t *)rsrc->ptr;
	if (lock->type == IS_UV_RWLOCK) {
		if (lock->locked == 0x01) {
			php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uv_rwlock: unlocked resoruce detected. force rdunlock resource.");
			uv_rwlock_rdunlock(&lock->lock.rwlock);
			lock->locked = 0x00;
		} else if (lock->locked == 0x02) {
			php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uv_rwlock: unlocked resoruce detected. force wrunlock resource.");
			uv_rwlock_wrunlock(&lock->lock.rwlock);
			lock->locked = 0x00;
		}
		uv_rwlock_destroy(&lock->lock.rwlock);
	} else if (lock->type == IS_UV_MUTEX) {
		if (lock->locked == 0x01) {
			php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uv_mutex: unlocked resoruce detected. force unlock resource.");
			uv_mutex_unlock(&lock->lock.mutex);
			lock->locked = 0x00;
		}
		uv_mutex_destroy(&lock->lock.mutex);
	}

	efree(lock);
}

void static destruct_uv_loop(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	uv_loop_t *loop = (uv_loop_t *)rsrc->ptr;
	if (loop != _php_uv_default_loop) {
		uv_loop_delete(loop);
	}
}

void static destruct_uv_sockaddr(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	php_uv_sockaddr_t *addr = (php_uv_sockaddr_t *)rsrc->ptr;
	efree(addr);
}

static uv_loop_t *php_uv_default_loop()
{
	if (_php_uv_default_loop == NULL) {
		_php_uv_default_loop = uv_default_loop();
	}
	
	return _php_uv_default_loop;
}

void static destruct_uv_ares(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	int base_id = -1;
	php_uv_ares_t *obj = (php_uv_ares_t *)rsrc->ptr;
	PHP_UV_DEBUG_PRINT("# will be free: (resource_id: %d)", obj->resource_id);

	if (obj->gethostbyname_cb) {
		//fprintf(stderr, "udp_send_cb: %d\n", Z_REFCOUNT_P(obj->listen_cb));
		zval_ptr_dtor(&obj->gethostbyname_cb);
		obj->gethostbyname_cb = NULL;
	}

	if (obj != NULL) {
		efree(obj);
		obj = NULL;
	}
	
	if (base_id) {
		//fprintf(stderr,"resource_refcount:%d\n",rsrc->refcount);
		zend_list_delete(base_id);
	}
}

void static destruct_uv(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	int base_id = -1;
	php_uv_t *obj = NULL;

	if (rsrc->ptr == NULL) {
		return;
	}
	
	obj = (php_uv_t *)rsrc->ptr;
	if (obj == NULL) {
		return;
	}

	PHP_UV_DEBUG_PRINT("# will be free: (resource_id: %d)\n", obj->resource_id);
	
	if (obj->in_free > 0) {
		PHP_UV_DEBUG_PRINT("# resource_id: %d is freeing. prevent double free.\n", obj->resource_id);
		return;
	}

	obj->in_free = 1;

	if (obj->address) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: address\n");
		zval_ptr_dtor(&obj->address);
		obj->address = NULL;
	}
	if (obj->read_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: read_cb\n");
		zval_ptr_dtor(&obj->read_cb);
		obj->read_cb = NULL;
	}
	if (obj->read2_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: read2_cb\n");
		zval_ptr_dtor(&obj->read2_cb);
		obj->read2_cb = NULL;
	}
	if (obj->write_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: write_cb\n");
		zval_ptr_dtor(&obj->write_cb);
		obj->write_cb = NULL;
	}
	if (obj->shutdown_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: shutdown_cb\n");
		zval_ptr_dtor(&obj->shutdown_cb);
		obj->shutdown_cb = NULL;
	}
	if (obj->close_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: close_cb\n");
		zval_ptr_dtor(&obj->close_cb);
		obj->close_cb = NULL;
	}
	if (obj->listen_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: listen_cb\n");
		zval_ptr_dtor(&obj->listen_cb);
		obj->listen_cb = NULL;
	}
	if (obj->idle_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: idle_cb\n");
		zval_ptr_dtor(&obj->idle_cb);
		obj->idle_cb = NULL;
	}
	if (obj->connect_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: connect_cb\n");
		zval_ptr_dtor(&obj->connect_cb);
		obj->connect_cb = NULL;
	}
	if (obj->udp_recv_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: udp_recb_cb\n");
		zval_ptr_dtor(&obj->udp_recv_cb);
		obj->udp_recv_cb = NULL;
	}
	if (obj->udp_send_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: udp_send_cb\n");
		zval_ptr_dtor(&obj->udp_send_cb);
		obj->udp_send_cb = NULL;
	}
	if (obj->pipe_connect_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: pipe_connect_cb\n");
		zval_ptr_dtor(&obj->pipe_connect_cb);
		obj->pipe_connect_cb = NULL;
	}
	if (obj->proc_close_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: proc_close_cb\n");
		zval_ptr_dtor(&obj->proc_close_cb);
		obj->proc_close_cb = NULL;
	}
	if (obj->prepare_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: prepare_cb\n");
		zval_ptr_dtor(&obj->prepare_cb);
		obj->prepare_cb = NULL;
	}
	if (obj->check_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: check_cb\n");
		zval_ptr_dtor(&obj->check_cb);
		obj->check_cb = NULL;
	}
	if (obj->async_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: async_cb\n");
		zval_ptr_dtor(&obj->async_cb);
		obj->async_cb = NULL;
	}
	if (obj->work_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: work_cb\n");
		zval_ptr_dtor(&obj->work_cb);
		obj->work_cb = NULL;
	}
	if (obj->after_work_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: after_work_cb\n");
		zval_ptr_dtor(&obj->after_work_cb);
		obj->after_work_cb = NULL;
	}
	if (obj->fs_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: fs_cb\n");
		zval_ptr_dtor(&obj->fs_cb);
		obj->fs_cb = NULL;
	}
	if (obj->getaddr_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: getaddr_cb\n");
		zval_ptr_dtor(&obj->getaddr_cb);
		obj->getaddr_cb = NULL;
	}
	if (obj->timer_cb) {
		PHP_UV_DEBUG_PRINT("zval_ptr_dtor: timer_cb\n");
		zval_ptr_dtor(&obj->timer_cb);
		obj->timer_cb = NULL;
	}

	if (obj->resource_id) {
		base_id = obj->resource_id;
		obj->resource_id = 0;
	}

	if (obj != NULL) {
		efree(obj);
		obj = NULL;
		rsrc->ptr = NULL;
	}
}

/* callback */

static int php_uv_do_callback(zval **retval_ptr, zval *callback, zval ***params, int param_count TSRMLS_DC)
{
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;
	char *is_callable_error = NULL;
	int error;
	
	if(zend_fcall_info_init(callback, 0, &fci, &fcc, NULL, &is_callable_error TSRMLS_CC) == SUCCESS) {
		if (is_callable_error) {
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "to be a valid callback");
		}
	}
	fci.retval_ptr_ptr = retval_ptr;
	fci.params = params;
	fci.param_count = param_count;
	
	error = zend_call_function(&fci, &fcc TSRMLS_CC);
	return error;
}

static void php_uv_tcp_connect_cb(uv_connect_t *req, int status)
{
	zval *retval_ptr, *stat, *client= NULL;
	zval **params[2];
	php_uv_t *uv = (php_uv_t*)req->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);
	
	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);
	MAKE_STD_ZVAL(client);
	ZVAL_RESOURCE(client, uv->resource_id);

	params[0] = &client;
	params[1] = &stat;
	
	php_uv_do_callback(&retval_ptr, uv->connect_cb, params, 2 TSRMLS_CC);
	
	zval_ptr_dtor(&retval_ptr);
	zval_ptr_dtor(&stat);
	zval_ptr_dtor(&client);
	efree(req);
}

static void php_uv_process_close_cb(uv_process_t* process, int exit_status, int term_signal)
{
	zval *retval_ptr, *signal, *stat, *proc= NULL;
	zval **params[3];
	php_uv_t *uv = (php_uv_t*)process->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);
	
	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, exit_status);
	MAKE_STD_ZVAL(signal);
	ZVAL_LONG(signal, term_signal);
	MAKE_STD_ZVAL(proc);
	ZVAL_RESOURCE(proc, uv->resource_id);

	params[0] = &proc;
	params[1] = &stat;
	params[2] = &signal;
	
	php_uv_do_callback(&retval_ptr, uv->proc_close_cb, params, 3 TSRMLS_CC);
	
	zval_ptr_dtor(&retval_ptr);
	zval_ptr_dtor(&stat);
	zval_ptr_dtor(&proc);
	zval_ptr_dtor(&signal);
}


static void php_uv_pipe_connect_cb(uv_connect_t *req, int status)
{
	zval *retval_ptr, *stat, *client= NULL;
	zval **params[2];
	php_uv_t *uv = (php_uv_t*)req->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);
	
	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);
	MAKE_STD_ZVAL(client);
	ZVAL_RESOURCE(client, uv->resource_id);

	params[0] = &stat;
	params[1] = &client;
	
	php_uv_do_callback(&retval_ptr, uv->pipe_connect_cb, params, 2 TSRMLS_CC);
	
	zval_ptr_dtor(&retval_ptr);
	zval_ptr_dtor(&stat);
	zval_ptr_dtor(&client);
	efree(req);
}


static void php_uv_write_cb(uv_write_t* req, int status)
{
	write_req_t* wr = (write_req_t*) req;
	zval *retval_ptr, *stat, *client= NULL;
	zval **params[2];
	php_uv_t *uv = (php_uv_t*)req->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("uv_write_cb: status: %d\n", status);
	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);
	
	MAKE_STD_ZVAL(client);
	ZVAL_RESOURCE(client, uv->resource_id);
	//zend_list_addref(uv->resource_id);

	params[0] = &client;
	params[1] = &stat;
	
	php_uv_do_callback(&retval_ptr, uv->write_cb, params, 2 TSRMLS_CC);

	zval_ptr_dtor(&retval_ptr);
	zval_ptr_dtor(&stat);
	zval_ptr_dtor(&client);

	if (wr->buf.base) {
		//free(wr->buf.base);
	}
	efree(wr);
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_write_cb, uv->resource_id);
}

static void php_uv_udp_send_cb(uv_udp_send_t* req, int status)
{

	send_req_t* wr = (send_req_t*) req;
	zval *retval_ptr, *stat, *client= NULL;
	zval **params[2];
	php_uv_t *uv = (php_uv_t*)req->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);

	MAKE_STD_ZVAL(client);
	ZVAL_RESOURCE(client, uv->resource_id);

	params[0] = &client;
	params[1] = &stat;
	
	php_uv_do_callback(&retval_ptr, uv->udp_send_cb, params, 2 TSRMLS_CC);

	zval_ptr_dtor(&stat);
	zval_ptr_dtor(&client);

	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}

	if (wr->buf.base) {
		efree(wr->buf.base);
	}
	efree(wr);
}

static void php_uv_listen_cb(uv_stream_t* server, int status)
{
	zval *retval_ptr, *stat, *svr= NULL;
	zval **params[2];
	php_uv_t *uv = (php_uv_t*)server->data;

	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	MAKE_STD_ZVAL(svr);
	ZVAL_RESOURCE(svr, uv->resource_id);
	zend_list_addref(uv->resource_id);
	
	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);

	params[0] = &svr;
	params[1] = &stat;

	php_uv_do_callback(&retval_ptr, uv->listen_cb, params, 2 TSRMLS_CC);
	
	zval_ptr_dtor(&svr);
	zval_ptr_dtor(&stat);
	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}
}

static void php_uv_close_cb2(uv_handle_t *handle)
{
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);
	PHP_UV_DEBUG_PRINT("uv_close_cb2:\n");

	zend_list_delete(uv->resource_id);

	// maybe we can't call efree at here.
	//efree(handle);
}

static void php_uv_shutdown_cb(uv_shutdown_t* handle, int status)
{
	zval *retval_ptr = NULL;
	zval **params[2];
	zval *h, *stat;
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	MAKE_STD_ZVAL(h);
	ZVAL_RESOURCE(h, uv->resource_id);

	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);

	if (uv->shutdown_cb != NULL) {
		params[0] = &h;
		params[1] = &stat;
		php_uv_do_callback(&retval_ptr, uv->shutdown_cb, params, 2 TSRMLS_CC);
		if (retval_ptr != NULL) {
			zval_ptr_dtor(&retval_ptr);
		}
	}

	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_shutdown_cb, uv->resource_id);
	
	zval_ptr_dtor(&h);
	zval_ptr_dtor(&stat);
	efree(handle);
}

static void php_uv_read_cb(uv_stream_t* handle, ssize_t nread, uv_buf_t buf)
{
	zval *rsc, *buffer, *err, *retval_ptr = NULL;
	zval **params[3];
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("uv_read_cb\n");

	if (nread < 0) {
		/* does this should be in user-land ? */
		//uv_shutdown_t* req;
		
		/* Error or EOF */
		//assert(uv_last_error(uv_default_loop()).code == UV_EOF);
		//if (buf.base) {
		//	efree(buf.base);
		//}
		
		//req = (uv_shutdown_t*) emalloc(sizeof *req);
		//PHP_UV_DEBUG_PRINT("uv_read_cb: read close\n");

		//uv_shutdown(req, (uv_handle_t *)handle, php_uv_shutdown_cb);
		//return;
	}
	
	if (nread == 0) {
		/* Everything OK, but nothing read. */
		//efree(buf.base);
		//return;
	}
	

	MAKE_STD_ZVAL(buffer);
	if (nread > 0) {
		ZVAL_STRINGL(buffer,buf.base,nread, 1);
	} else {
		ZVAL_NULL(buffer);
	}

	MAKE_STD_ZVAL(rsc);
	ZVAL_RESOURCE(rsc, uv->resource_id);
	zend_list_addref(uv->resource_id);
	
	MAKE_STD_ZVAL(err)
	ZVAL_LONG(err, nread);

	params[0] = &rsc;
	params[1] = &err;
	params[2] = &buffer;
	
	php_uv_do_callback(&retval_ptr, uv->read_cb, params, 3 TSRMLS_CC);

	zval_ptr_dtor(&buffer);
	zval_ptr_dtor(&rsc);
	zval_ptr_dtor(&err);
	
	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}

	if (buf.base) {
		efree(buf.base);
	}
	
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_read_cb, uv->resource_id);
}

static void php_uv_read2_cb(uv_pipe_t* handle, ssize_t nread, uv_buf_t buf, uv_handle_type pending)
{
	zval *rsc, *buffer, *err, *pend, *retval_ptr = NULL;
	zval **params[4];
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("uv_read2_cb\n");

	MAKE_STD_ZVAL(buffer);
	if (nread > 0) {
		ZVAL_STRINGL(buffer,buf.base,nread, 1);
	} else {
		ZVAL_NULL(buffer);
	}

	MAKE_STD_ZVAL(rsc);
	ZVAL_RESOURCE(rsc, uv->resource_id);
	//zend_list_addref(uv->resource_id);
	
	MAKE_STD_ZVAL(err)
	ZVAL_LONG(err, nread);
	
	MAKE_STD_ZVAL(pend);
	ZVAL_LONG(pend, pending);

	params[0] = &rsc;
	params[1] = &err;
	params[2] = &buffer;
	params[3] = &pend;
	
	php_uv_do_callback(&retval_ptr, uv->read2_cb, params, 4 TSRMLS_CC);

	zval_ptr_dtor(&buffer);
	zval_ptr_dtor(&rsc);
	zval_ptr_dtor(&err);
	zval_ptr_dtor(&pend);
	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}

	if (buf.base) {
		efree(buf.base);
	}
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_read2_cb, uv->resource_id);
}

static void php_uv_prepare_cb(uv_prepare_t* handle, int status)
{
	zval *retval_ptr = NULL;
	zval **params[1];
	zval *zstat;
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("prepare_cb\n");

	MAKE_STD_ZVAL(zstat);
	ZVAL_LONG(zstat, status);

	params[0] = &zstat;
	
	php_uv_do_callback(&retval_ptr, uv->prepare_cb, params, 1 TSRMLS_CC);

	zval_ptr_dtor(&zstat);
	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_prepare_cb, uv->resource_id);
}

static void php_uv_check_cb(uv_check_t* handle, int status)
{
	zval *retval_ptr = NULL;
	zval **params[1];
	zval *zstat;
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("check_cb\n");

	MAKE_STD_ZVAL(zstat);
	ZVAL_LONG(zstat, status);

	params[0] = &zstat;
	
	php_uv_do_callback(&retval_ptr, uv->check_cb, params, 1 TSRMLS_CC);

	zval_ptr_dtor(&zstat);
	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_check_cb, uv->resource_id);
}


static void php_uv_async_cb(uv_async_t* handle, int status)
{
	zval *retval_ptr = NULL;
	zval **params[1];
	zval *zstat;
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("async_cb\n");

	MAKE_STD_ZVAL(zstat);
	ZVAL_LONG(zstat, status);

	params[0] = &zstat;
	
	php_uv_do_callback(&retval_ptr, uv->async_cb, params, 1 TSRMLS_CC);

	zval_ptr_dtor(&zstat);
	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_async_cb, uv->resource_id);
}


static void php_uv_work_cb(uv_work_t* req)
{
	zval *retval_ptr = NULL;
	php_uv_t *uv;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	uv = (php_uv_t*)req->data;

	PHP_UV_DEBUG_PRINT("work_cb\n");

	php_uv_do_callback(&retval_ptr, uv->work_cb, NULL, 0 TSRMLS_CC);
	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_work_cb, uv->resource_id);
}

static void php_uv_after_work_cb(uv_work_t* req)
{
	zval *retval_ptr = NULL;
	php_uv_t *uv = (php_uv_t*)req->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("after_work_cb\n");

	php_uv_do_callback(&retval_ptr, uv->after_work_cb, NULL, 0 TSRMLS_CC);
	zval_ptr_dtor(&retval_ptr);
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_after_work_cb, uv->resource_id);
}

static void php_uv_fs_cb(uv_fs_t* req)
{
	zval **params[3], *result, *retval_ptr = NULL;
	php_uv_t *uv = (php_uv_t*)req->data;
	int argc = 2;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("# php_uv_fs_cb %d\n", uv->resource_id);

	MAKE_STD_ZVAL(result);
	ZVAL_LONG(result, uv->uv.fs.result);
	params[0] = &result;

	switch (uv->uv.fs.fs_type) {
		case UV_FS_SYMLINK:
		case UV_FS_LINK:
		case UV_FS_CHMOD:
		case UV_FS_FCHMOD:
		case UV_FS_RENAME:
		case UV_FS_UNLINK:
		case UV_FS_RMDIR:
		case UV_FS_MKDIR:
		case UV_FS_FTRUNCATE:
		case UV_FS_FDATASYNC:
		case UV_FS_FSYNC:
		case UV_FS_CLOSE:
		case UV_FS_CHOWN:
		case UV_FS_FCHOWN:
			argc = 1;
			break;
		case UV_FS_OPEN:
		{
			argc = 1;
			break;
		}
		case UV_FS_READDIR:
		{
			zval *dirent;
			int nnames, i = 0;
			char *namebuf = (char *)req->ptr;
			
			MAKE_STD_ZVAL(dirent);
			array_init(dirent);
			
			nnames = req->result;
			for (i = 0; i < nnames; i++) {
				add_next_index_string(dirent, namebuf, 1);
				namebuf += strlen(namebuf) + 1;
			}
			
			params[1] = &dirent;
		break;
		}
		case UV_FS_LSTAT:
		case UV_FS_FSTAT:
		case UV_FS_STAT:
		{
			zval *buffer;
			buffer = php_uv_make_stat((const uv_statbuf_t*)req->ptr);
			params[1] = &buffer;
			break;
		}
		case UV_FS_UTIME:
		case UV_FS_FUTIME:
			argc = 0;
			break;
		case UV_FS_READLINK:
		{
			zval *buffer;
			
			MAKE_STD_ZVAL(buffer);
			ZVAL_STRING(buffer, req->ptr, 1);
			params[1] = &buffer;
			break;
		}
		case UV_FS_READ:
		{
			argc = 3;
			zval *buffer;
			zval *nread;
			MAKE_STD_ZVAL(buffer);
			MAKE_STD_ZVAL(nread);
			
			if (uv->uv.fs.result > 0) {
				ZVAL_STRINGL(buffer, uv_fs_read_buf, uv->uv.fs.result, 1);
			} else {
				ZVAL_NULL(buffer);
			}
			ZVAL_LONG(nread, uv->uv.fs.result);
			
			params[1] = &nread;
			params[2] = &buffer;
			break;
		}
		case UV_FS_SENDFILE:
		{
			zval *res;
			argc = 2;

			MAKE_STD_ZVAL(res);
			ZVAL_LONG(res, uv->uv.fs.result);

			params[1] = &res;
			break;
		}
		case UV_FS_WRITE:
		{
			zval *res;
			argc = 1;
			MAKE_STD_ZVAL(res);
			ZVAL_LONG(res, uv->uv.fs.result);

			params[1] = &res;
			efree(uv->buffer);
			break;
		}
		default: {
			fprintf(stderr,"type; %d does not support yet.", uv->uv.fs.fs_type);
			break;
		}
	}

	php_uv_do_callback(&retval_ptr, uv->fs_cb, params, argc TSRMLS_CC);
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_fs_cb, uv->resource_id);
	
	if (argc == 2) {
		zval_ptr_dtor(params[1]);
	} else if (argc == 3) {
		zval_ptr_dtor(params[1]);
		zval_ptr_dtor(params[2]);
	}

	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}
	zval_ptr_dtor(&result);

	uv_fs_req_cleanup(req);
}

static void php_uv_fs_event_cb(uv_fs_event_t* req, const char* filename, int events, int status)
{
	zval **params[3];
	zval *name,*ev,*stat,*rsc,*retval_ptr = NULL;
	php_uv_t *uv = (php_uv_t*)req->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("fs_event_cb: %s, %d\n", filename, status);

	MAKE_STD_ZVAL(rsc);
	MAKE_STD_ZVAL(name);
	MAKE_STD_ZVAL(ev);
	MAKE_STD_ZVAL(stat);
	if (filename) {
		ZVAL_STRING(name,filename,1);
	} else {
		ZVAL_NULL(name);
	}
	ZVAL_LONG(ev, events);
	ZVAL_LONG(stat, status);
	ZVAL_RESOURCE(rsc, uv->resource_id);
	zend_list_addref(uv->resource_id);
	
	params[0] = &rsc;
	params[1] = &name;
	params[2] = &ev;
	params[3] = &stat;

	php_uv_do_callback(&retval_ptr, uv->fs_event_cb, params, 4 TSRMLS_CC);

	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}

	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_fs_event_cb, uv->resource_id);
	zval_ptr_dtor(params[0]);
	zval_ptr_dtor(params[1]);
	zval_ptr_dtor(params[2]);
	zval_ptr_dtor(params[3]);
}


static void php_uv_udp_recv_cb(uv_udp_t* handle, ssize_t nread, uv_buf_t buf, struct sockaddr* addr, unsigned flags)
{
	/* TODO: is this implment correct? */
	zval *retval_ptr = NULL;
	zval **params[3];
	zval *buffer, *rsc, *read;
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);
	
	MAKE_STD_ZVAL(buffer);
	ZVAL_STRINGL(buffer,buf.base,nread, 1);

	MAKE_STD_ZVAL(rsc);
	ZVAL_RESOURCE(rsc, uv->resource_id);
	
	MAKE_STD_ZVAL(read);
	ZVAL_LONG(read, nread);

	params[0] = &rsc;
	params[1] = &read;
	params[2] = &buffer;
	
	php_uv_do_callback(&retval_ptr, uv->udp_recv_cb, params, 3 TSRMLS_CC);

	zval_ptr_dtor(&buffer);
	zval_ptr_dtor(&rsc);
	zval_ptr_dtor(&read);
	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}

	if (buf.base) {
		efree(buf.base);
	}
}

static uv_buf_t php_uv_read_alloc(uv_handle_t* handle, size_t suggested_size)
{
	return uv_buf_init(emalloc(suggested_size), suggested_size);
}


static void php_uv_close_cb(uv_handle_t *handle)
{
	zval *retval_ptr = NULL;
	zval **params[1];
	zval *h;

	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);
	MAKE_STD_ZVAL(h);
	ZVAL_RESOURCE(h, uv->resource_id);

	if (uv->close_cb != NULL) {
		params[0] = &h;
		php_uv_do_callback(&retval_ptr, uv->close_cb, params, 1 TSRMLS_CC);
		if (retval_ptr != NULL) {
			zval_ptr_dtor(&retval_ptr);
		}
	}
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_close_cb, uv->resource_id);
	zend_hash_index_del(&EG(regular_list), uv->resource_id);

	zval_ptr_dtor(&h); /* call destruct_uv */
}


static void php_uv_idle_cb(uv_timer_t *handle, int status)
{
	zval *retval_ptr, *stat = NULL;
	zval **params[1];

	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);
	
	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);
	params[0] = &stat;
	
	php_uv_do_callback(&retval_ptr, uv->idle_cb, params, 1 TSRMLS_CC);

	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}
	zval_ptr_dtor(&stat);
}

static void php_uv_getaddrinfo_cb(uv_getaddrinfo_t* handle, int status, struct addrinfo* res)
{
	zval *tmp, *retval_ptr, *stat = NULL;
	zval **params[2];
	struct addrinfo *address;
	char ip[INET6_ADDRSTRLEN];
	const char *addr;
	
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);
	
	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);
	params[0] = &stat;

	MAKE_STD_ZVAL(tmp);
	array_init(tmp);
	
	address = res;
	while (address) {
		if (address->ai_family == AF_INET) {
			const char *c;
			
			addr = (char*) &((struct sockaddr_in*) address->ai_addr)->sin_addr;
			c = uv_inet_ntop(address->ai_family, addr, ip, INET6_ADDRSTRLEN);
			add_next_index_string(tmp, c, 1);
		}
		
		address = address->ai_next;
	}

	address = res;
	while (address) {
		if (address->ai_family == AF_INET6) {
			const char *c;

			addr = (char*) &((struct sockaddr_in6*) address->ai_addr)->sin6_addr;
			c = uv_inet_ntop(address->ai_family, addr, ip, INET6_ADDRSTRLEN);
			add_next_index_string(tmp, c, 1);
		}
		
		address = address->ai_next;
	}

	params[1] = &tmp;
	
	php_uv_do_callback(&retval_ptr, uv->getaddr_cb, params, 2 TSRMLS_CC);
	
	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}
	zval_ptr_dtor(&stat);
	zval_ptr_dtor(&tmp);
	
	zend_list_delete(uv->resource_id);
	uv_freeaddrinfo(res);
}

static void php_uv_timer_cb(uv_timer_t *handle, int status)
{
	zval *retval_ptr, *stat, *client= NULL;
	zval **params[2];
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);
	
	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);
	MAKE_STD_ZVAL(client);
	ZVAL_RESOURCE(client, uv->resource_id);
	zend_list_addref(uv->resource_id);

	params[0] = &stat;
	params[1] = &client;
	
	php_uv_do_callback(&retval_ptr, uv->timer_cb, params, 2 TSRMLS_CC);

	if (retval_ptr != NULL) {
		zval_ptr_dtor(&retval_ptr);
	}
	zval_ptr_dtor(&stat);
	zval_ptr_dtor(&client);
}

static inline uv_stream_t* php_uv_get_current_stream(php_uv_t *uv)
{
	uv_stream_t *stream;
	switch(uv->type) {
		case IS_UV_TCP:
			stream = (uv_stream_t*)&uv->uv.tcp;
		break;
		case IS_UV_UDP:
			stream = (uv_stream_t*)&uv->uv.udp;
		break;
		case IS_UV_PIPE:
			stream = (uv_stream_t*)&uv->uv.pipe;
		break;
		case IS_UV_IDLE:
			stream = (uv_stream_t*)&uv->uv.idle;
		break;
		case IS_UV_TIMER:
			stream = (uv_stream_t*)&uv->uv.timer;
		break;
		case IS_UV_ASYNC:
			stream = (uv_stream_t*)&uv->uv.async;
		break;
		case IS_UV_LOOP:
			stream = (uv_stream_t*)&uv->uv.loop;
		break;
		case IS_UV_HANDLE:
			stream = (uv_stream_t*)&uv->uv.handle;
		break;
		case IS_UV_STREAM:
			stream = (uv_stream_t*)&uv->uv.stream;
		break;
		case IS_UV_PROCESS:
			stream = (uv_stream_t*)&uv->uv.process;
		break;
		case IS_UV_PREPARE:
			stream = (uv_stream_t*)&uv->uv.prepare;
		break;
		case IS_UV_CHECK:
			stream = (uv_stream_t*)&uv->uv.check;
		break;
		case IS_UV_FS_EVENT:
			stream = (uv_stream_t*)&uv->uv.fs_event;
		break;
		default: {
			TSRMLS_FETCH();
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "unexpected type found");
			break;
		}
	}
	
	return stream;
}

void static destruct_httpparser(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	http_parser *obj = (http_parser *)rsrc->ptr;

	efree(obj);
}

/*  http parser callbacks */
int on_message_begin(http_parser *p)
{
	return 0;
}

int on_headers_complete(http_parser *p)
{
	return 0;
}

int on_message_complete(http_parser *p)
{
	php_http_parser_context *result = p->data;
	result->finished = 1;

	return 0;
}

#define PHP_HTTP_PARSER_PARSE_URL(flag, name) \
	if (result->handle.field_set & (1 << flag)) { \
		const char *name = at+result->handle.field_data[flag].off; \
		int length = result->handle.field_data[flag].len; \
		add_assoc_stringl(data, #name, (char*)name, length, 1); \
	} 

int on_url_cb(http_parser *p, const char *at, size_t len)
{
	php_http_parser_context *result = p->data;
	zval *data = result->data;

	http_parser_parse_url(at, len, 0, &result->handle);

	add_assoc_stringl(data, "QUERY_STRING", (char*)at, len, 1);

	PHP_HTTP_PARSER_PARSE_URL(UF_SCHEMA, scheme);
	PHP_HTTP_PARSER_PARSE_URL(UF_HOST, host);
	PHP_HTTP_PARSER_PARSE_URL(UF_PORT, port);
	PHP_HTTP_PARSER_PARSE_URL(UF_PATH, path);
	PHP_HTTP_PARSER_PARSE_URL(UF_QUERY, query);
	PHP_HTTP_PARSER_PARSE_URL(UF_FRAGMENT, fragment);

	return 0;
}

int header_field_cb(http_parser *p, const char *at, size_t len)
{
	php_http_parser_context *result = p->data;
	/* TODO: */
	result->tmp = estrndup(at, len);

	return 0;
}

int header_value_cb(http_parser *p, const char *at, size_t len)
{
	php_http_parser_context *result = p->data;
	zval *data = result->headers;

	add_assoc_stringl(data, result->tmp, (char*)at, len, 1);
	/* TODO: */
	efree(result->tmp);
	result->tmp = NULL;
	return 0;
}

int on_body_cb(http_parser *p, const char *at, size_t len)
{
	php_http_parser_context *result = p->data;
	zval *data = result->headers;

	add_assoc_stringl(data, "body", (char*)at, len,  1);

	return 0;
}
/* end of callback */


/* zend */

PHP_MINIT_FUNCTION(uv)
{
	php_uv_init(TSRMLS_C);
	uv_resource_handle = zend_register_list_destructors_ex(destruct_uv, NULL, PHP_UV_RESOURCE_NAME, module_number);
	uv_ares_handle     = zend_register_list_destructors_ex(destruct_uv_ares, NULL, PHP_UV_ARES_RESOURCE_NAME, module_number);
	uv_loop_handle     = zend_register_list_destructors_ex(destruct_uv_loop, NULL, PHP_UV_LOOP_RESOURCE_NAME, module_number);
	uv_sockaddr_handle = zend_register_list_destructors_ex(destruct_uv_sockaddr, NULL, PHP_UV_SOCKADDR_RESOURCE_NAME, module_number);
	uv_lock_handle   = zend_register_list_destructors_ex(destruct_uv_lock, NULL, PHP_UV_LOCK_RESOURCE_NAME, module_number);
	uv_httpparser_handle = zend_register_list_destructors_ex(destruct_httpparser, NULL, PHP_UV_HTTPPARSER_RESOURCE_NAME, module_number);

	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(uv)
{
	php_uv_ares_destroy();
	return SUCCESS;
}


ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_run_once, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_run, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_loop_delete, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_now, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_connect, 0, 0, 2)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_connect6, 0, 0, 2)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_init, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_listen, 0, 0, 3)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, backlog)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_accept, 0, 0, 2)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, client)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_read_start, 0, 0, 2)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_read2_start, 0, 0, 2)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_read_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, server)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_write, 0, 0, 2)
	ZEND_ARG_INFO(0, client)
	ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_last_error, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_strerror, 0, 0, 1)
	ZEND_ARG_INFO(0, error)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_err_name, 0, 0, 1)
	ZEND_ARG_INFO(0, error)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_init, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_idle_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, idle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_again, 0, 0, 1)
	ZEND_ARG_INFO(0, idle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_start, 0, 0, 4)
	ZEND_ARG_INFO(0, timer)
	ZEND_ARG_INFO(0, timeout)
	ZEND_ARG_INFO(0, repeat)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, timer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_again, 0, 0, 1)
	ZEND_ARG_INFO(0, timer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_set_repeat, 0, 0, 2)
	ZEND_ARG_INFO(0, timer)
	ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_get_repeat, 0, 0, 2)
	ZEND_ARG_INFO(0, timer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_idle_start, 0, 0, 2)
	ZEND_ARG_INFO(0, timer)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_bind, 0, 0, 1)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, address)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_bind6, 0, 0, 1)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, address)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_shutdown, 0, 0, 2)
	ZEND_ARG_INFO(0, stream)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_close, 0, 0, 2)
	ZEND_ARG_INFO(0, stream)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_idle_init, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_update_time, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_is_active, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_is_readable, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_is_writable, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_ref, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_unref, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_nodelay, 0, 0, 2)
	ZEND_ARG_INFO(0, tcp)
	ZEND_ARG_INFO(0, enabled)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_ip4_addr, 0, 0, 2)
	ZEND_ARG_INFO(0, address)
	ZEND_ARG_INFO(0, port)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_ip6_addr, 0, 0, 2)
	ZEND_ARG_INFO(0, address)
	ZEND_ARG_INFO(0, port)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_init, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_bind, 0, 0, 3)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, address)
	ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_bind6, 0, 0, 3)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, address)
	ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_recv_start, 0, 0, 2)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_recv_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, server)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_set_multicast_loop, 0, 0, 2)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, enabled)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_set_multicast_ttl, 0, 0, 2)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, ttl)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_set_broadcast, 0, 0, 2)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, enabled)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_send, 0, 0, 4)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, buffer)
	ZEND_ARG_INFO(0, address)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_pipe_open, 0, 0, 2)
	ZEND_ARG_INFO(0, file)
	ZEND_ARG_INFO(0, pipe)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_pipe_init, 0, 0, 1)
	ZEND_ARG_INFO(0, file)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_pipe_bind, 0, 0, 2)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_pipe_connect, 0, 0, 3)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, name)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_pipe_pending_instances, 0, 0, 2)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_spawn, 0, 0, 5)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, command)
	ZEND_ARG_INFO(0, args)
	ZEND_ARG_INFO(0, options)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_kill, 0, 0, 2)
	ZEND_ARG_INFO(0, pid)
	ZEND_ARG_INFO(0, signal)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_process_kill, 0, 0, 2)
	ZEND_ARG_INFO(0, process)
	ZEND_ARG_INFO(0, signal)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_chdir, 0, 0, 1)
	ZEND_ARG_INFO(0, dir)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tty_get_winsize, 0, 0, 3)
	ZEND_ARG_INFO(0, tty)
	ZEND_ARG_INFO(1, width)
	ZEND_ARG_INFO(1, height)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tty_init, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, readable)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_event_init, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, callback)
	ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_sendfile, 0, 0, 5)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, in)
	ZEND_ARG_INFO(0, out)
	ZEND_ARG_INFO(0, offset)
	ZEND_ARG_INFO(0, length)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_readdir, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, flags)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_fstat, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_lstat, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_stat, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_readlink, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_symlink, 0, 0, 5)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, from)
	ZEND_ARG_INFO(0, to)
	ZEND_ARG_INFO(0, callback)
	ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_link, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, from)
	ZEND_ARG_INFO(0, to)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_fchown, 0, 0, 5)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, uid)
	ZEND_ARG_INFO(0, gid)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_chown, 0, 0, 5)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, uid)
	ZEND_ARG_INFO(0, gid)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_fchmod, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, mode)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_chmod, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, mode)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_futime, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, utime)
	ZEND_ARG_INFO(0, atime)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_utime, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, utime)
	ZEND_ARG_INFO(0, atime)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_open, 0, 0, 5)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, flag)
	ZEND_ARG_INFO(0, mode)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_read, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_close, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_write, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, buffer)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_fsync, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_fdatasync, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_ftruncate, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, offset)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_mkdir, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, mode)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_rmdir, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_unlink, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_rename, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, from)
	ZEND_ARG_INFO(0, to)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_rwlock_rdlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_rwlock_tryrdlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_rwlock_rdunlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_rwlock_wrlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_rwlock_trywrlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_rwlock_wrunlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_mutex_lock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_mutex_trylock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_mutex_unlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_prepare_init, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_prepare_start, 0, 0, 2)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_prepare_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_check_init, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_check_start, 0, 0, 2)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_check_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_async_send, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_async_init, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_ares_gethostbyname, 0, 0, 3)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, name)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_ares_init_options, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, options)
	ZEND_ARG_INFO(0, mask)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_getsockname, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_getpeername, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_getsockname, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_set_membership, 0, 0, 4)
	ZEND_ARG_INFO(0, client)
	ZEND_ARG_INFO(0, multicast_addr)
	ZEND_ARG_INFO(0, interface_addr)
	ZEND_ARG_INFO(0, membership)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_ip6_name, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_ip4_name, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

/* PHP Functions */

/* {{{ */
PHP_FUNCTION(uv_unref)
{
	zval *handle = NULL;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z",&handle) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	uv_unref((uv_handle_t *)php_uv_get_current_stream(uv));
	zend_list_delete(uv->resource_id);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_last_error)
{
	uv_loop_t *loop;
	uv_err_t err;
	zval *z_loop = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z",&z_loop) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	err = uv_last_error(loop);

	RETVAL_LONG(err.code);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_err_name)
{
	long error_code;
	const char *error_msg;
	uv_err_t error;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"l",&error_code) == FAILURE) {
		return;
	}
	error.code = error_code;
	
	error_msg = uv_err_name(error);
	RETVAL_STRING(error_msg,1);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_strerror)
{
	long error_code;
	const char *error_msg;
	uv_err_t error;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"l",&error_code) == FAILURE) {
		return;
	}
	error.code = error_code;
	
	error_msg = uv_strerror(error);
	RETVAL_STRING(error_msg,1);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_update_time)
{
	zval *z_loop = NULL;
	uv_loop_t *loop;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z",&z_loop) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	uv_update_time(loop);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_ref)
{
	zval *handle = NULL;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z",&handle) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	uv_ref((uv_handle_t *)php_uv_get_current_stream(uv));
	zend_list_addref(uv->resource_id);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_run)
{
	zval *z_loop = NULL;
	uv_loop_t *loop;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|z",&z_loop) == FAILURE) {
		return;
	}
	if (z_loop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = php_uv_default_loop();
	}
	
	uv_run(loop);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_run_once)
{
	zval *z_loop = NULL;
	uv_loop_t *loop;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|z",&z_loop) == FAILURE) {
		return;
	}
	if (z_loop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = php_uv_default_loop();
	}
	
	uv_run_once(loop);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_loop_delete)
{
	zval *z_loop = NULL;
	uv_loop_t *loop;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z",&z_loop) == FAILURE) {
		return;
	}

	if (z_loop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
		uv_loop_delete(loop);
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_now)
{
	zval *z_loop = NULL;
	uv_loop_t *loop;
	int64_t now;
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z",&z_loop) == FAILURE) {
		return;
	}

	if (z_loop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
		now = uv_now(loop);
		RETURN_LONG((long)now);
	}
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_tcp_bind)
{
	zval *resource, *address;
	php_uv_sockaddr_t *addr;
	php_uv_t *uv;
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zz",&resource, &address) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &resource, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	ZEND_FETCH_RESOURCE(addr, php_uv_sockaddr_t *, &address, -1, PHP_UV_SOCKADDR_RESOURCE_NAME, uv_sockaddr_handle);

	r = uv_tcp_bind((uv_tcp_t*)&uv->uv.tcp, addr->addr.ipv4);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "bind failed");
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_tcp_bind6)
{
	zval *resource, *address;
	php_uv_sockaddr_t *addr;
	php_uv_t *uv;
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zz",&resource, &address) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &resource, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	ZEND_FETCH_RESOURCE(addr, php_uv_sockaddr_t *, &address, -1, PHP_UV_SOCKADDR_RESOURCE_NAME, uv_sockaddr_handle);
	Z_ADDREF_P(resource);
	
	r = uv_tcp_bind6((uv_tcp_t*)&uv->uv.tcp, addr->addr.ipv6);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "bind failed");
	}
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_write)
{
	zval *z_cli,*callback;
	char *data;
	int data_len = 0;
	php_uv_t *uv;
	write_req_t *w;
	int r = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zsz",&z_cli, &data, &data_len,&callback) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &z_cli, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	Z_ADDREF_P(callback);
	uv->write_cb = callback;
	zend_list_addref(uv->resource_id);

	w = emalloc(sizeof(write_req_t));
	w->req.data = uv;
	w->buf = uv_buf_init(data, data_len);

	r = uv_write(&w->req, (uv_stream_t*)php_uv_get_current_stream(uv), &w->buf, 1, php_uv_write_cb);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "write failed");
	}

	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_write, uv->resource_id);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_tcp_nodelay)
{
	zval *z_cli;
	php_uv_t *client;
	long bval = 1;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zl",&z_cli, &bval) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(client, php_uv_t *, &z_cli, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	uv_tcp_nodelay(&client->uv.tcp, bval);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_accept)
{
	zval *z_svr,*z_cli;
	php_uv_t *server, *client;
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zz",&z_svr, &z_cli) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(server, php_uv_t *, &z_svr, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	ZEND_FETCH_RESOURCE(client, php_uv_t *, &z_cli, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	
	r = uv_accept((uv_stream_t *)php_uv_get_current_stream(server), (uv_stream_t *)php_uv_get_current_stream(client));
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "accept");
	}
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_shutdown)
{
	zval *client, *callback = NULL;
	php_uv_t *uv;
	uv_shutdown_t *shutdown;
	int r = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r|z",&client, &callback) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &client, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	if (callback != NULL) {
		Z_ADDREF_P(callback);
		uv->shutdown_cb = callback;
	}

	zend_list_addref(uv->resource_id);
	shutdown = emalloc(sizeof(uv_shutdown_t));
	shutdown->data = uv;
	
	r = uv_shutdown(shutdown, (uv_stream_t*)php_uv_get_current_stream(uv), (uv_shutdown_cb)php_uv_shutdown_cb);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "%s (ERRNO: %d)", uv_strerror(uv_last_error(uv_default_loop())), r);
	}

}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_close)
{
	zval *client, *callback = NULL;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r|z",&client, &callback) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &client, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	if (callback != NULL) {
		Z_ADDREF_P(callback);
		uv->close_cb = callback;
	}
	
	zend_list_addref(uv->resource_id);
	uv_close((uv_handle_t*)php_uv_get_current_stream(uv), (uv_close_cb)php_uv_close_cb);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_read_start)
{
	zval *client, *callback;
	php_uv_t *uv;
	int r;

	PHP_UV_DEBUG_PRINT("uv_read_start\n");

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rz",&client, &callback) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &client, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	Z_ADDREF_P(callback);
	zend_list_addref(uv->resource_id);

	uv->read_cb = callback;
	if(uv->type == IS_UV_TCP) {
		uv->uv.tcp.data = uv;
	} else if(uv->type == IS_UV_PIPE) {
		uv->uv.pipe.data = uv;
	} else {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "this type does not support yet");
	}

	r = uv_read_start((uv_stream_t*)php_uv_get_current_stream(uv), php_uv_read_alloc, php_uv_read_cb);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "read failed");
	}
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_read_start, uv->resource_id);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_read2_start)
{
	zval *client, *callback;
	php_uv_t *uv;
	int r;

	PHP_UV_DEBUG_PRINT("uv_read2_start\n");

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rz",&client, &callback) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &client, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	Z_ADDREF_P(callback);
	zend_list_addref(uv->resource_id);

	uv->read2_cb = callback;
	if(uv->type == IS_UV_TCP) {
		uv->uv.tcp.data = uv;
	} else if(uv->type == IS_UV_PIPE) {
		uv->uv.pipe.data = uv;
	} else {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "this type does not support yet");
	}

	r = uv_read2_start((uv_stream_t*)php_uv_get_current_stream(uv), php_uv_read_alloc, php_uv_read2_cb);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "read2 failed");
	}
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_read2_start, uv->resource_id);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_read_stop)
{
	zval *server;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r", &server) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &server, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	uv_read_stop((uv_stream_t*)php_uv_get_current_stream(uv));
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_read_stop, uv->resource_id);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_ip4_addr)
{
	char *address;
	int address_len = 0;
	long port = 0;
	php_uv_sockaddr_t *sockaddr;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"sl",&address, &address_len, &port) == FAILURE) {
		return;
	}
	
	sockaddr = (php_uv_sockaddr_t*)emalloc(sizeof(php_uv_sockaddr_t));
	
	sockaddr->is_ipv4 = 1;
	sockaddr->addr.ipv4 = uv_ip4_addr(address, port);
	
	ZEND_REGISTER_RESOURCE(return_value, sockaddr, uv_sockaddr_handle);
	sockaddr->resource_id = Z_LVAL_P(return_value);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_ip6_addr)
{
	char *address;
	int address_len = 0;
	long port = 0;
	php_uv_sockaddr_t *sockaddr;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"sl",&address, &address_len, &port) == FAILURE) {
		return;
	}
	
	sockaddr = (php_uv_sockaddr_t*)emalloc(sizeof(php_uv_sockaddr_t));
	
	sockaddr->is_ipv4 = 0;
	sockaddr->addr.ipv6 = uv_ip6_addr(address, port);
	
	ZEND_REGISTER_RESOURCE(return_value, sockaddr, uv_sockaddr_handle);
	sockaddr->resource_id = Z_LVAL_P(return_value);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_listen)
{
	zval *resource, *callback;
	long backlog = SOMAXCONN;
	php_uv_t *uv;
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zlz",&resource, &backlog, &callback) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &resource, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	Z_ADDREF_P(callback);
	uv->listen_cb = callback;

	r = uv_listen((uv_stream_t*)php_uv_get_current_stream(uv), backlog, php_uv_listen_cb);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "%s", uv_strerror(uv_last_error(uv_default_loop())));
	}
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_tcp_connect)
{
	zval *resource,*address, *callback;
	php_uv_t *uv;
	php_uv_sockaddr_t *addr;
	uv_connect_t *req;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zzz",&resource,&address, &callback) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &resource, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	ZEND_FETCH_RESOURCE(addr, php_uv_sockaddr_t *, &address, -1, PHP_UV_SOCKADDR_RESOURCE_NAME, uv_sockaddr_handle);
	zend_list_addref(uv->resource_id);
	Z_ADDREF_P(callback);
	Z_ADDREF_P(address);
	
	req = (uv_connect_t*)emalloc(sizeof(uv_connect_t));
	
	req->data = uv;
	uv->address = address;
	uv->connect_cb = callback;
	uv_tcp_connect(req, &uv->uv.tcp, addr->addr.ipv4, php_uv_tcp_connect_cb);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_tcp_connect6)
{
	zval *resource,*address, *callback;
	php_uv_t *uv;
	php_uv_sockaddr_t *addr;
	uv_connect_t *req;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zzz",&resource,&address, &callback) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &resource, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	ZEND_FETCH_RESOURCE(addr, php_uv_sockaddr_t *, &address, -1, PHP_UV_SOCKADDR_RESOURCE_NAME, uv_sockaddr_handle);
	zend_list_addref(uv->resource_id);
	Z_ADDREF_P(callback);
	Z_ADDREF_P(address);
	
	req = (uv_connect_t*)emalloc(sizeof(uv_connect_t));
	
	req->data = uv;
	uv->address = address;
	uv->connect_cb = callback;
	uv_tcp_connect6(req, &uv->uv.tcp, addr->addr.ipv6, php_uv_tcp_connect_cb);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_timer_init)
{
	int r;
	zval *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|z",&zloop) == FAILURE) {
		return;
	}
	if (zloop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = uv_default_loop();
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));

	r = uv_timer_init(loop, &uv->uv.timer);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_timer_init failed");
		return;
	}
	uv->type = IS_UV_TIMER;
	uv->uv.timer.data = uv;
	PHP_UV_INIT_ZVALS(uv)
	TSRMLS_SET_CTX(uv->thread_ctx);
	
	ZEND_REGISTER_RESOURCE(return_value, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(return_value);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_timer_start)
{
//int uv_timer_start(uv_timer_t* handle, uv_timer_cb timer_cb, int64_t timeout,int64_t repeat) {
	zval *timer, *callback;
	php_uv_t *uv;
	long timeout, repeat = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rllz",&timer, &timeout, &repeat, &callback) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &timer, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	Z_ADDREF_P(callback);
	zend_list_addref(uv->resource_id);

	uv->timer_cb = callback;
	uv_timer_start((uv_timer_t*)&uv->uv.timer, php_uv_timer_cb, timeout, repeat);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_timer_stop)
{
	zval *timer;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r",&timer) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &timer, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);

	uv_timer_stop((uv_timer_t*)&uv->uv.timer);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_timer_again)
{
	zval *timer;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r",&timer) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &timer, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);

	uv_timer_again((uv_timer_t*)&uv->uv.timer);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_timer_set_repeat)
{
	zval *timer;
	php_uv_t *uv;
	long repeat;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rl",&timer,&repeat) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &timer, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);

	uv_timer_set_repeat((uv_timer_t*)&uv->uv.timer,repeat);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_timer_get_repeat)
{
	zval *timer;
	php_uv_t *uv;
	int64_t repeat;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r",&timer) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &timer, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);

	repeat = uv_timer_get_repeat((uv_timer_t*)&uv->uv.timer);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_idle_start)
{
	zval *idle, *callback;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rz",&idle, &callback) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &idle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	Z_ADDREF_P(callback);
	zend_list_addref(uv->resource_id);
	
	if (uv->idle_cb) {
		zval_ptr_dtor(&uv->idle_cb);
		uv->idle_cb = NULL;
	}

	uv->idle_cb = callback;
	uv_idle_start((uv_idle_t*)&uv->uv.idle, (uv_idle_cb)php_uv_idle_cb);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_getaddrinfo)
{
	zval *z_loop, *hints, *callback = NULL;
	uv_loop_t *loop;
	php_uv_t *uv = NULL;
	struct addrinfo hint = {0};
	char *node, *service;
	int node_len, service_len = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zzss|a",&z_loop, &callback, &node, &node_len, &service, &service_len, &hints) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	Z_ADDREF_P(callback);
	
	if (Z_TYPE_P(hints) == IS_ARRAY) {
		HashTable *h;
		zval **data;
		
		h = Z_ARRVAL_P(hints);
		if (zend_hash_find(h, "ai_family", sizeof("ai_family"), (void **)&data) == SUCCESS) {
			hint.ai_family = Z_LVAL_PP(data);
		}
		if (zend_hash_find(h, "ai_socktype", sizeof("ai_socktype"), (void **)&data) == SUCCESS) {
			hint.ai_socktype = Z_LVAL_PP(data);
		}
		if (zend_hash_find(h, "ai_protocol", sizeof("ai_socktype"), (void **)&data) == SUCCESS) {
			hint.ai_socktype = Z_LVAL_PP(data);
		}
		if (zend_hash_find(h, "ai_flags", sizeof("ai_flags"), (void **)&data) == SUCCESS) {
			hint.ai_flags = Z_LVAL_PP(data);
		}
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));
	PHP_UV_INIT_ZVALS(uv)
	TSRMLS_SET_CTX(uv->thread_ctx);
	uv->getaddr_cb = callback;
	uv->uv.addrinfo.data = uv;
	uv->resource_id = PHP_UV_LIST_INSERT(uv, uv_resource_handle);

	uv_getaddrinfo(loop, &uv->uv.addrinfo, php_uv_getaddrinfo_cb, node, service, &hint);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_idle_stop)
{
	zval *idle;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r", &idle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &idle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	uv_idle_stop((uv_idle_t*)&uv->uv.idle);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_tcp_init)
{
	int r;
	zval *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|z",&zloop) == FAILURE) {
		return;
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));
	if (!uv) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_tcp_init emalloc failed");
		return;
	}
	if (zloop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = uv_default_loop();
	}

	uv->type = IS_UV_TCP;
	r = uv_tcp_init(loop, &uv->uv.tcp);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_tcp_init failed");
		return;
	}
	
	uv->uv.tcp.data = uv;
	PHP_UV_INIT_ZVALS(uv)
	TSRMLS_SET_CTX(uv->thread_ctx);
	
	ZEND_REGISTER_RESOURCE(return_value, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(return_value);
}
/* }}} */
	
/* {{{ */
PHP_FUNCTION(uv_idle_init)
{
	int r;
	zval *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|z",&zloop) == FAILURE) {
		return;
	}
	if (zloop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = uv_default_loop();
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));

	r = uv_idle_init(loop, &uv->uv.idle);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_idle_init failed");
		return;
	}
	uv->uv.timer.data = uv;
	PHP_UV_INIT_ZVALS(uv)
	TSRMLS_SET_CTX(uv->thread_ctx);
	
	ZEND_REGISTER_RESOURCE(return_value, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(return_value);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_default_loop)
{
	ZEND_REGISTER_RESOURCE(return_value, php_uv_default_loop(), uv_loop_handle);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_udp_init)
{
	int r;
	zval *zloop;
	uv_loop_t *loop = NULL;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|z",&zloop) == FAILURE) {
		return;
	}
	if (loop) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = uv_default_loop();
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));
	if (!uv) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_udp_init emalloc failed");
		return;
	}

	uv->type = IS_UV_UDP;
	r = uv_udp_init(loop, &uv->uv.udp);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_udp_init failed");
		return;
	}
	
	uv->uv.udp.data = uv;
	PHP_UV_INIT_ZVALS(uv)
	TSRMLS_SET_CTX(uv->thread_ctx);
	
	ZEND_REGISTER_RESOURCE(return_value, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(return_value);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_udp_bind)
{
	zval *resource, *address;
	long flags = 0;
	php_uv_sockaddr_t *addr;
	php_uv_t *uv;
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zz|l",&resource, &address, &flags) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &resource, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	ZEND_FETCH_RESOURCE(addr, php_uv_sockaddr_t *, &address, -1, PHP_UV_SOCKADDR_RESOURCE_NAME, uv_sockaddr_handle);
	
	r = uv_udp_bind((uv_udp_t*)&uv->uv.udp, addr->addr.ipv4, flags);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_udp_bind failed");
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_udp_bind6)
{
	zval *resource, *address;
	long flags = 0;
	php_uv_sockaddr_t *addr;
	php_uv_t *uv;
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zz|l",&resource, &address, &flags) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &resource, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	ZEND_FETCH_RESOURCE(addr, php_uv_sockaddr_t *, &address, -1, PHP_UV_SOCKADDR_RESOURCE_NAME, uv_sockaddr_handle);
	
	r = uv_udp_bind6((uv_udp_t*)&uv->uv.udp, addr->addr.ipv6, flags);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_udp_bind6 failed");
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_udp_recv_start)
{
	zval *client, *callback;
	php_uv_t *uv;
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rz",&client, &callback) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &client, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	Z_ADDREF_P(callback);
	zend_list_addref(uv->resource_id);

	uv->udp_recv_cb = callback;
	uv->uv.udp.data = uv;

	r = uv_udp_recv_start((uv_udp_t*)&uv->uv.udp, php_uv_read_alloc, php_uv_udp_recv_cb);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "read failed");
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_udp_recv_stop)
{
	zval *client;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r", &client) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &client, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	
	uv_udp_recv_stop((uv_udp_t*)&uv->uv.udp);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_udp_set_membership)
{
	zval *client;
	php_uv_t *uv;
	char *multicast_addr, interface_addr;
	int error, multicast_addr_len, interface_addr_len = 0;
	long membership;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rssl", &client, &multicast_addr, &multicast_addr_len, &interface_addr, &interface_addr_len, &membership) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &client, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	
	error = uv_udp_set_membership((uv_udp_t*)&uv->uv.udp, (const char*)multicast_addr, (const char*)interface_addr, (int)membership);

	RETURN_LONG(error);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_udp_set_multicast_loop)
{
	zval *client;
	php_uv_t *uv;
	long enabled = 0;
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rl",&client, &enabled) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &client, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);

	r = uv_udp_set_multicast_loop((uv_udp_t*)&uv->uv.udp, enabled);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uv_udp_set_muticast_loop failed");
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_udp_set_multicast_ttl)
{
	zval *client;
	php_uv_t *uv;
	long ttl = 0; /* 1 through 255 */
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rl",&client, &ttl) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &client, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);

	r = uv_udp_set_multicast_ttl((uv_udp_t*)&uv->uv.udp, ttl);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uv_udp_set_muticast_ttl failed");
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_udp_set_broadcast)
{
	zval *client;
	php_uv_t *uv;
	long enabled = 0;
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rl",&client, &enabled) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &client, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);

	r = uv_udp_set_broadcast((uv_udp_t*)&uv->uv.udp, enabled);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "uv_udp_set_muticast_loop failed");
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_udp_send)
{
	zval *z_cli,*z_addr, *callback;
	char *data;
	int data_len = 0;
	php_uv_t *client;
	send_req_t *w;
	php_uv_sockaddr_t *addr;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zszz",&z_cli, &data, &data_len, &z_addr, &callback) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(client, php_uv_t *, &z_cli, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	ZEND_FETCH_RESOURCE(addr, php_uv_sockaddr_t *, &z_addr, -1, PHP_UV_SOCKADDR_RESOURCE_NAME, uv_sockaddr_handle);

	Z_ADDREF_P(callback);
	client->udp_send_cb = callback;
	zend_list_addref(client->resource_id);

	w = emalloc(sizeof(send_req_t));
	w->req.data = client;
	w->buf = uv_buf_init(estrndup(data,data_len), data_len);
	uv_udp_send(&w->req, &client->uv.udp, &w->buf, 1, addr->addr.ipv4, php_uv_udp_send_cb);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_is_active)
{
	zval *handle;
	php_uv_t *uv;
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r",&handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);

	r = uv_is_active((uv_handle_t*)php_uv_get_current_stream(uv));
	RETURN_BOOL(r);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_is_readable)
{
	zval *handle;
	php_uv_t *uv;
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r",&handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);

	r = uv_is_readable((uv_stream_t*)php_uv_get_current_stream(uv));
	RETURN_BOOL(r);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_is_writable)
{
	zval *handle;
	php_uv_t *uv;
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r",&handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);

	r = uv_is_writable((uv_stream_t*)php_uv_get_current_stream(uv));
	RETURN_BOOL(r);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_pipe_init)
{
	php_uv_t *uv;
	uv_loop_t *loop;
	zval *z_loop;
	long ipc = 0;
	int r;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|z|l", &z_loop, &ipc) == FAILURE) {
		return;
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));
	if (!uv) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_pipe_init emalloc failed");
		return;
	}
	
	if (Z_TYPE_P(z_loop) == IS_RESOURCE) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = php_uv_default_loop();
	}

	uv->type = IS_UV_PIPE;
	r = uv_pipe_init(loop, &uv->uv.pipe, ipc);
	
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_pipe_init failed");
		return;
	}

	uv->uv.pipe.data = uv;
	PHP_UV_INIT_ZVALS(uv)
	TSRMLS_SET_CTX(uv->thread_ctx);
	
	ZEND_REGISTER_RESOURCE(return_value, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(return_value);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_pipe_open)
{
	php_uv_t *uv;
	zval *handle;
	/* TODO: `pipe` correct? */
	long pipe = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zl",&handle, &pipe) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);

	uv_pipe_open(&uv->uv.pipe, pipe);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_pipe_bind)
{
	php_uv_t *uv;
	zval *handle;
	char *name;
	int error, name_len = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zs",&handle, &name, &name_len) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	error = uv_pipe_bind(&uv->uv.pipe, name);
	if (error) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", uv_strerror(uv_last_error(uv_default_loop())));
	}
	RETURN_LONG(error);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_pipe_connect)
{
	zval *resource, *callback;
	zval *address = NULL;
	php_uv_t *uv;
	char *name;
	int name_len = 0;
	uv_connect_t *req;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zsz",&resource,&name, &name_len, &callback) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &resource, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	Z_ADDREF_P(callback);
	zend_list_addref(uv->resource_id);
	
	req = (uv_connect_t*)emalloc(sizeof(uv_connect_t));
	
	req->data = uv;
	uv->address = address;
	uv->pipe_connect_cb = callback;
	uv_pipe_connect(req, (uv_pipe_t*)php_uv_get_current_stream(uv), name, php_uv_pipe_connect_cb);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_pipe_pending_instances)
{
	php_uv_t *uv;
	zval *handle;
	long count;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zl",&handle, &count) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	uv_pipe_pending_instances(&uv->uv.pipe, count);
}
/* }}} */


static void php_ares_gethostbyname_cb( void *arg, int status, int timeouts, struct hostent *hostent)
{
	TSRMLS_FETCH();
	zval *retval_ptr, *hostname, *addresses = NULL;
	zval **params[2];
	php_uv_ares_t *uv = (php_uv_ares_t*)arg;
	struct in_addr **ptr;

	MAKE_STD_ZVAL(hostname);
	ZVAL_STRING(hostname, hostent->h_name, 1);
	MAKE_STD_ZVAL(addresses);

	array_init(addresses);
	ptr = (struct in_addr **)hostent->h_addr_list;
	while(*ptr != NULL) {
		add_next_index_string(addresses, inet_ntoa(**(ptr++)), 1);
	}

	params[0] = &hostname;
	params[1] = &addresses;
	
	php_uv_do_callback(&retval_ptr, uv->gethostbyname_cb, params, 2 TSRMLS_CC);

	zval_ptr_dtor(&retval_ptr);
	zval_ptr_dtor(&hostname);
	zval_ptr_dtor(&addresses);
}

/* {{{ */
PHP_FUNCTION(uv_ares_init_options)
{
	int rc, length;
	int optmask = ARES_OPT_SERVERS | ARES_OPT_TCP_PORT | ARES_OPT_LOOKUPS | ARES_OPT_FLAGS;
	zval **data, *zoptions, *zloop = NULL;
	uv_loop_t *loop = NULL;
	php_uv_ares_t *uv;
	HashTable *h;
	struct in_addr *addresses;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zal",&zloop,&zoptions, &optmask) == FAILURE) {
		return;
	}
	
	if (Z_TYPE_P(zloop) == IS_RESOURCE) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = php_uv_default_loop();
	}
	
	uv = (php_uv_ares_t*)emalloc(sizeof(php_uv_ares_t));
	uv->gethostbyname_cb = NULL;
	
	h = Z_ARRVAL_P(zoptions);
	if (zend_hash_find(h, "servers", sizeof("servers"), (void **)&data) == SUCCESS) {
		HashTable *servers = Z_ARRVAL_P(*data);
		HashPosition pos;
		char *key;
		int key_type;
		uint key_len;
		ulong key_index;
		int i = 0;
		
		length = zend_hash_num_elements(servers);
		addresses = (struct in_addr*)ecalloc(length, sizeof(struct in_addr));
		for (zend_hash_internal_pointer_reset_ex(servers, &pos);
			(key_type = zend_hash_get_current_key_ex(servers, &key, &key_len, &key_index, 0, &pos)) != HASH_KEY_NON_EXISTANT;
			zend_hash_move_forward_ex(servers, &pos)) {
			struct sockaddr_in address;
			zval **value;
			
			zend_hash_get_current_data_ex(servers, (void *) &value, &pos);
			if (Z_TYPE_PP(value) != IS_STRING) {
				php_error_docref(NULL TSRMLS_CC, E_ERROR, "servers value must be an array");
			}

			address = uv_ip4_addr(Z_STRVAL_PP(value),0);
			addresses[i] = address.sin_addr;
		}
		
	}
	if (zend_hash_find(h, "port", sizeof("port"), (void **)&data) == SUCCESS) {
		uv->options.tcp_port = htonl(Z_LVAL_PP(data));
	}
	if (zend_hash_find(h, "lookups", sizeof("lookups"), (void **)&data) == SUCCESS) {
		uv->options.lookups = Z_STRVAL_PP(data);
	}

	uv->options.servers  = addresses;
	uv->options.nservers = length;
	uv->options.flags    = ARES_FLAG_USEVC;

	if (uv_ares_initialized == 0) {
		php_uv_ares_init(TSRMLS_C);
	}

	rc = uv_ares_init_options(loop, &uv->channel, &uv->options, optmask);
	if (rc) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_ares_init_options failed");
	}
	efree(addresses);

	ZEND_REGISTER_RESOURCE(return_value, uv, uv_ares_handle);
	uv->resource_id = Z_LVAL_P(return_value);
}


/* {{{ */
PHP_FUNCTION(ares_gethostbyname)
{
	zval *handle, *byname_cb;
	long flag = AF_INET;
	char *name;
	int name_len;
	php_uv_ares_t *uv;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zslz",&handle, &name, &name_len, &flag, &byname_cb) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_ares_t *, &handle, -1, PHP_UV_ARES_RESOURCE_NAME, uv_ares_handle);
	if (uv->gethostbyname_cb != NULL) {
		zval_ptr_dtor(&uv->gethostbyname_cb);
		uv->gethostbyname_cb = NULL;
	}
	Z_ADDREF_P(byname_cb);
	uv->gethostbyname_cb = byname_cb;
	
	ares_gethostbyname(uv->channel,
		name,
		flag,
		&php_ares_gethostbyname_cb,
		uv
	);
}
/* }}} */

/* {{{ proto array uv_loadavg(void)
*/
PHP_FUNCTION(uv_loadavg)
{
	zval *retval;
	double average[3];

	uv_loadavg(average);
	
	MAKE_STD_ZVAL(retval);
	array_init(retval);
	add_next_index_double(retval, average[0]);
	add_next_index_double(retval, average[1]);
	add_next_index_double(retval, average[2]);
	
	RETURN_ZVAL(retval,0,1);
}
/* }}} */

/* {{{ proto double uv_uptime(void)
*/
PHP_FUNCTION(uv_uptime)
{
	uv_err_t error;
	double uptime;

	error = uv_uptime(&uptime);
	
	RETURN_DOUBLE(uptime);
}
/* }}} */

/* {{{ proto long uv_get_free_memory(void)
*/
PHP_FUNCTION(uv_get_free_memory)
{
	RETURN_LONG(uv_get_free_memory());
}
/* }}} */

/* {{{ proto long uv_get_total_memory(void)
*/
PHP_FUNCTION(uv_get_total_memory)
{
	RETURN_LONG(uv_get_total_memory());
}
/* }}} */

/* {{{ proto long uv_hrtime(void)
*/
PHP_FUNCTION(uv_hrtime)
{
	/* TODO: is this correct? */
	RETURN_LONG(uv_hrtime());
}
/* }}} */

/* {{{ proto string uv_exepath(void)
*/
PHP_FUNCTION(uv_exepath)
{
	char buffer[1024] = {0};
	size_t buffer_sz;
	
	buffer_sz = sizeof(buffer);
	uv_exepath(buffer, &buffer_sz);
	buffer[buffer_sz] = '\0';
	
	RETURN_STRINGL(buffer, buffer_sz, 1);
}
/* }}} */

/* {{{ proto string uv_cwd(void) */
PHP_FUNCTION(uv_cwd)
{
	char buffer[1024] = {0};
	size_t buffer_sz = sizeof(buffer);
	
	uv_cwd(buffer, buffer_sz);
	buffer[buffer_sz] = '\0';
	
	RETURN_STRING(buffer, 1);
}
/* }}} */

/* {{{ proto array uv_cpu_info(void)
*/
PHP_FUNCTION(uv_cpu_info)
{
	zval *retval;
	uv_cpu_info_t *cpus;
	uv_err_t error;
	int i, count;

	error = uv_cpu_info(&cpus, &count);
	if (UV_OK == error.code) {
		MAKE_STD_ZVAL(retval);
		array_init(retval);
		
		for (i = 0; i < count; i++) {
			zval *tmp, *times;

			MAKE_STD_ZVAL(tmp);
			MAKE_STD_ZVAL(times);
			array_init(tmp);
			array_init(times);

			add_assoc_string_ex(tmp, "model", sizeof("model"), cpus[i].model, 1);
			add_assoc_long_ex(tmp,   "speed", sizeof("speed"), cpus[i].speed);

			add_assoc_long_ex(times, "sys",   sizeof("sys"),  (size_t)cpus[i].cpu_times.sys);
			add_assoc_long_ex(times, "user",  sizeof("user"), (size_t)cpus[i].cpu_times.user);
			add_assoc_long_ex(times, "idle",  sizeof("idle"), (size_t)cpus[i].cpu_times.idle);
			add_assoc_long_ex(times, "irq",   sizeof("irq"),  (size_t)cpus[i].cpu_times.irq);
			add_assoc_long_ex(times, "nice",  sizeof("nice"), (size_t)cpus[i].cpu_times.nice);
			add_assoc_zval_ex(tmp,   "times", sizeof("times"), times);

			add_next_index_zval(retval,tmp);
		}
		
		uv_free_cpu_info(cpus, count);
		RETURN_ZVAL(retval,0,1);
	}
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_interface_addresses)
{
	zval *retval;
	uv_interface_address_t *interfaces;
	uv_err_t error;
	char buffer[512];
	int i, count;

	error = uv_interface_addresses(&interfaces, &count);
	if (UV_OK == error.code) {
		MAKE_STD_ZVAL(retval);
		array_init(retval);
		
		for (i = 0; i < count; i++) {
			zval *tmp;
			MAKE_STD_ZVAL(tmp);
			array_init(tmp);
			add_assoc_string_ex(tmp, "name", sizeof("name"), interfaces[i].name , 1);
			add_assoc_bool_ex(tmp, "is_internal", sizeof("is_internal"), interfaces[i].is_internal);

			if (interfaces[i].address.address4.sin_family == AF_INET) {
				uv_ip4_name(&interfaces[i].address.address4, buffer, sizeof(buffer));
			} else if (interfaces[i].address.address4.sin_family == AF_INET6) {
				uv_ip6_name(&interfaces[i].address.address6, buffer, sizeof(buffer));
			}
			add_assoc_string_ex(tmp, "address", sizeof("address"), buffer, 1);

			add_next_index_zval(retval,tmp);
		}
		uv_free_interface_addresses(interfaces, count);
		RETURN_ZVAL(retval,0,1);
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_spawn)
{
	zval *zloop = NULL;
	uv_loop_t *loop;
	uv_process_options_t options = {0};
	uv_stdio_container_t stdio[3];
	php_uv_t *proc;
	zval *args, *context, *callback;
	char **zenv;
	char *command;
	char **command_args;
	int command_len = 0;

	options.stdio = stdio;
	options.stdio_count = 3;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zsaaz", &zloop, &command, &command_len, &args, &context, &callback) == FAILURE) {
		return;
	}
	
	if (zloop) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = uv_default_loop();
	}

	{
		HashTable *h;
		zval **data;
		h = Z_ARRVAL_P(context);

		if (zend_hash_find(h, "cwd", sizeof("cwd"), (void **)&data) == SUCCESS) {
			options.cwd = Z_STRVAL_PP(data);
		}
		
		if (zend_hash_find(h, "env", sizeof("env"), (void **)&data) == SUCCESS) {
			HashTable *env;
			HashPosition pos;
			char *key;
			int key_type;
			uint key_len;
			ulong key_index;
			int i = 0;
			
			env = Z_ARRVAL_P(*data);

			zenv = emalloc(sizeof(char*) * (zend_hash_num_elements(env)+1));
			for (zend_hash_internal_pointer_reset_ex(env, &pos);
				(key_type = zend_hash_get_current_key_ex(env, &key, &key_len, &key_index, 0, &pos)) != HASH_KEY_NON_EXISTANT;
				zend_hash_move_forward_ex(env, &pos)) {

				zval **value;
				char *hoge;
				zend_hash_get_current_data_ex(env, (void *) &value, &pos);
				
				hoge = emalloc(sizeof(char)*key_len+1+Z_STRLEN_PP(value));
				slprintf(hoge,key_len+1+Z_STRLEN_PP(value),"%s=%s",key, Z_STRVAL_PP(value));
				zenv[i] = hoge;
				i++;
			}
			zenv[i] = NULL;
			options.env = zenv;
		}
		
		if (zend_hash_find(h, "pipes", sizeof("pipes"), (void **)&data) == SUCCESS) {
			HashTable *pipes;
			HashPosition pos;
			char *key;
			int key_type;
			uint key_len;
			ulong key_index;
			
			pipes = Z_ARRVAL_P(*data);

			for (zend_hash_internal_pointer_reset_ex(pipes, &pos);
				(key_type = zend_hash_get_current_key_ex(pipes, &key, &key_len, &key_index, 0, &pos)) != HASH_KEY_NON_EXISTANT;
				zend_hash_move_forward_ex(pipes, &pos)) {

				zval **value;
				php_uv_t *pipe;
				
				zend_hash_get_current_data_ex(pipes, (void *) &value, &pos);
				if (Z_TYPE_PP(value) != IS_RESOURCE) {
					php_error_docref(NULL TSRMLS_CC, E_ERROR, "must be uv_pipe resource");
				}
				
				ZEND_FETCH_RESOURCE(pipe, php_uv_t *, value, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);

				if (pos->h == 0) {
					options.stdio[0].flags = UV_CREATE_PIPE | UV_READABLE_PIPE;
					options.stdio[0].data.stream = (uv_stream_t *)&pipe->uv.pipe;
				} else if (pos->h == 1) {
					options.stdio[1].flags = UV_CREATE_PIPE | UV_WRITABLE_PIPE;
					options.stdio[1].data.stream = (uv_stream_t *)&pipe->uv.pipe;
				} else if (pos->h == 2) {
					options.stdio[2].flags = UV_CREATE_PIPE | UV_WRITABLE_PIPE;
					options.stdio[2].data.stream = (uv_stream_t *)&pipe->uv.pipe;
				}
			}
			
		}
	}

	{
		HashTable *h;
		HashPosition pos;
		char *key;
		int key_type;
		uint key_len;
		ulong key_index;
		int hash_len = 0;

		h = Z_ARRVAL_P(args);
		hash_len = zend_hash_num_elements(h)+1;
		command_args = ecalloc(hash_len+1, sizeof(char**));
		command_args[0] = options.cwd;
		for (zend_hash_internal_pointer_reset_ex(h, &pos);
			(key_type = zend_hash_get_current_key_ex(h, &key, &key_len, &key_index, 0, &pos)) != HASH_KEY_NON_EXISTANT;
			zend_hash_move_forward_ex(h, &pos)) {

			zval **value;
			
			zend_hash_get_current_data_ex(h, (void *) &value, &pos);
			command_args[pos->h+1] = Z_STRVAL_PP(value);
		}
		command_args[hash_len] = NULL;
	}


	proc  = (php_uv_t *)emalloc(sizeof(php_uv_t));
	PHP_UV_INIT_ZVALS(proc);
	proc->proc_close_cb = callback;
	Z_ADDREF_P(callback);
	TSRMLS_SET_CTX(proc->thread_ctx);
	
	options.file          = command;
	if (command_args) {
		options.args = command_args;
	}
	options.exit_cb       = php_uv_process_close_cb;

	proc->type = IS_UV_PROCESS;
	proc->uv.process.data = proc;

	ZEND_REGISTER_RESOURCE(return_value, proc, uv_resource_handle);
	proc->resource_id = Z_LVAL_P(return_value);
	zval_copy_ctor(return_value);
	
	uv_spawn(loop, &proc->uv.process, options);
	
	if (zenv!=NULL) {
		char **p = zenv;
		while(*p != NULL) {
			efree(*p);
			p++;
		}
		efree(zenv);
	}
	if (command_args) {
		efree(command_args);
	}
}
/* }}} */


/* {{{ TODO: */
PHP_FUNCTION(uv_process_kill)
{
	php_uv_t *uv;
	zval *handle;
	int signal;
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zl", &handle, &signal) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	uv_process_kill(&uv->uv.process, signal);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_kill)
{
	long pid, signal;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"ll", &pid, &signal) == FAILURE) {
		return;
	}
	uv_kill(pid, signal);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_chdir)
{
	uv_err_t error;
	char *directory;
	int directory_len;
	

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"s", &directory, &directory_len) == FAILURE) {
		return;
	}
	error = uv_chdir(directory);
	if (error.code == UV_OK) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_rwlock_init)
{
	php_uv_lock_t *lock;
	int error;
	
	lock = emalloc(sizeof(php_uv_lock_t));
	error = uv_rwlock_init(&lock->lock.rwlock);
	if (error == 0) {
		ZEND_REGISTER_RESOURCE(return_value, lock, uv_lock_handle);
		lock->type = IS_UV_RWLOCK;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_rwlock_rdlock)
{
	php_uv_lock_t *lock;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(lock, php_uv_lock_t *, &handle, -1, PHP_UV_LOCK_RESOURCE_NAME, uv_lock_handle);
	lock->locked = 0x01;
	uv_rwlock_rdlock(&lock->lock.rwlock);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_rwlock_tryrdlock)
{
	php_uv_lock_t *lock;
	zval *handle;
	int error = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(lock, php_uv_lock_t *, &handle, -1, PHP_UV_LOCK_RESOURCE_NAME, uv_lock_handle);
	error = uv_rwlock_tryrdlock(&lock->lock.rwlock);
	if (error == 0) {
		lock->locked = 0x01;
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_rwlock_rdunlock)
{
	php_uv_lock_t *lock;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(lock, php_uv_lock_t *, &handle, -1, PHP_UV_LOCK_RESOURCE_NAME, uv_lock_handle);
	if (lock->locked == 0x01) {
		uv_rwlock_rdunlock(&lock->lock.rwlock);
		lock->locked = 0x00;
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_rwlock_wrlock)
{
	php_uv_lock_t *lock;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(lock, php_uv_lock_t *, &handle, -1, PHP_UV_LOCK_RESOURCE_NAME, uv_lock_handle);
	lock->locked = 0x02;
	uv_rwlock_wrlock(&lock->lock.rwlock);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_rwlock_trywrlock)
{
	php_uv_lock_t *lock;
	zval *handle;
	int error = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(lock, php_uv_lock_t *, &handle, -1, PHP_UV_LOCK_RESOURCE_NAME, uv_lock_handle);
	error = uv_rwlock_trywrlock(&lock->lock.rwlock);
	if (error == 0) {
		lock->locked = 0x02;
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_rwlock_wrunlock)
{
	php_uv_lock_t *lock;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(lock, php_uv_lock_t *, &handle, -1, PHP_UV_LOCK_RESOURCE_NAME, uv_lock_handle);
	if (lock->locked == 0x02) {
		uv_rwlock_wrunlock(&lock->lock.rwlock);
		lock->locked = 0x00;
	}
}
/* }}} */



/* {{{ proto uv_lock uv_mutex_init(void) */
PHP_FUNCTION(uv_mutex_init)
{
	php_uv_lock_t *mutex;
	int error;
	
	mutex = emalloc(sizeof(php_uv_t));
	error = uv_mutex_init(&mutex->lock.mutex);
	if (error == 0) {
		ZEND_REGISTER_RESOURCE(return_value, mutex, uv_lock_handle);
		mutex->type = IS_UV_MUTEX;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto void uv_mutex_lock(uv_lock $lock)*/
PHP_FUNCTION(uv_mutex_lock)
{
	php_uv_lock_t *mutex;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(mutex, php_uv_lock_t*, &handle, -1, PHP_UV_LOCK_RESOURCE_NAME, uv_lock_handle);
	uv_mutex_lock(&mutex->lock.mutex);
	mutex->locked = 0x01;
}
/* }}} */

/* {{{ proto: bool uv_mutex_trylock(uv_lock $lock) */
PHP_FUNCTION(uv_mutex_trylock)
{
	php_uv_lock_t *mutex;
	zval *handle;
	int error = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(mutex, php_uv_lock_t *, &handle, -1, PHP_UV_LOCK_RESOURCE_NAME, uv_lock_handle);
	error = uv_mutex_trylock(&mutex->lock.mutex);

	if (error == 0) {
		mutex->locked = 0x01;
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ void uv_mutex_unlock(uv_lock $lock) */
PHP_FUNCTION(uv_mutex_unlock)
{
	php_uv_lock_t *mutex;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(mutex, php_uv_lock_t *, &handle, -1, PHP_UV_LOCK_RESOURCE_NAME, uv_lock_handle);
	if (mutex->locked == 0x01) {
		uv_mutex_unlock(&mutex->lock.mutex);
		mutex->locked = 0x00;
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_prepare_init)
{
	int r;
	zval *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|z",&zloop) == FAILURE) {
		return;
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));
	if (!uv) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_prepare_init emalloc failed");
		return;
	}
	if (zloop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = uv_default_loop();
	}

	uv->type = IS_UV_PREPARE;
	r = uv_prepare_init(loop, &uv->uv.prepare);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_prepare_init failed");
		return;
	}
	
	uv->uv.prepare.data = uv;
	PHP_UV_INIT_ZVALS(uv)
	TSRMLS_SET_CTX(uv->thread_ctx);
	
	ZEND_REGISTER_RESOURCE(return_value, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(return_value);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_prepare_start)
{
	zval *handle, *callback;
	php_uv_t *uv;
	int r;

	PHP_UV_DEBUG_PRINT("uv_prepare_start\n");

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rz",&handle, &callback) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	Z_ADDREF_P(callback);
	zend_list_addref(uv->resource_id);

	uv->prepare_cb = callback;
	if(uv->type == IS_UV_PREPARE) {
		uv->uv.prepare.data = uv;
	} else {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "this type does not support yet");
	}

	r = uv_prepare_start((uv_prepare_t*)php_uv_get_current_stream(uv), php_uv_prepare_cb);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "read failed");
	}
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_prepare_start, uv->resource_id);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_prepare_stop)
{
	zval *handle;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	uv_prepare_stop((uv_prepare_t*)php_uv_get_current_stream(uv));
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_prepare_stop, uv->resource_id);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_check_init)
{
	int r;
	zval *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|z",&zloop) == FAILURE) {
		return;
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));
	if (!uv) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_check_init emalloc failed");
		return;
	}
	if (zloop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = uv_default_loop();
	}

	uv->type = IS_UV_CHECK;
	r = uv_check_init(loop, &uv->uv.check);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_check_init failed");
		return;
	}
	
	uv->uv.check.data = uv;
	PHP_UV_INIT_ZVALS(uv)
	TSRMLS_SET_CTX(uv->thread_ctx);
	
	ZEND_REGISTER_RESOURCE(return_value, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(return_value);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_check_start)
{
	zval *handle, *callback;
	php_uv_t *uv;
	int r;

	PHP_UV_DEBUG_PRINT("uv_check_start");

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rz",&handle, &callback) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	Z_ADDREF_P(callback);
	zend_list_addref(uv->resource_id);

	uv->check_cb = callback;
	if(uv->type == IS_UV_CHECK) {
		uv->uv.check.data = uv;
	} else {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "this type does not support yet");
	}

	r = uv_check_start((uv_check_t*)php_uv_get_current_stream(uv), php_uv_check_cb);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "read failed");
	}
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_check_start, uv->resource_id);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_check_stop)
{
	zval *handle;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	uv_check_stop((uv_check_t*)php_uv_get_current_stream(uv));
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_check_stop, uv->resource_id);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_async_init)
{
	int r;
	zval *zloop = NULL;
	zval *callback;
	uv_loop_t *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zz",&zloop, &callback) == FAILURE) {
		return;
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));
	if (!uv) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_check_init emalloc failed");
		return;
	}
	if (zloop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = uv_default_loop();
	}

	uv->type = IS_UV_ASYNC;
	r = uv_async_init(loop, &uv->uv.async, php_uv_async_cb);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_async_init failed");
		return;
	}
	
	uv->uv.async.data = uv;
	PHP_UV_INIT_ZVALS(uv)
	uv->async_cb = callback;
	Z_ADDREF_P(callback);
	TSRMLS_SET_CTX(uv->thread_ctx);
	
	ZEND_REGISTER_RESOURCE(return_value, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(return_value);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_async_send)
{
	zval *handle;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	uv_async_send((uv_async_t*)php_uv_get_current_stream(uv));
	PHP_UV_DEBUG_RESOURCE_REFCOUNT(uv_async_send, uv->resource_id);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_queue_work)
{
	int r;
	zval *zloop = NULL;
	zval *callback, *after_callback;
	uv_loop_t *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zzz",&zloop, &callback, &after_callback) == FAILURE) {
		return;
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));
	if (!uv) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_queue_work emalloc failed");
		return;
	}
	if (zloop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = uv_default_loop();
	}

	uv->type = IS_UV_WORK;
	PHP_UV_INIT_ZVALS(uv)

	uv->work_cb = callback;
	uv->after_work_cb = after_callback;
	Z_ADDREF_P(callback);
	Z_ADDREF_P(after_callback);
	uv->uv.work.data = uv;
	
	r = uv_queue_work(loop, (uv_work_t*)&uv->uv.work, php_uv_work_cb, php_uv_after_work_cb);

	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_async_init failed");
		return;
	}
	
	TSRMLS_SET_CTX(uv->thread_ctx);
	ZEND_REGISTER_RESOURCE(return_value, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(return_value);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_open)
{
	int r;
	zval *tmp, *zloop = NULL;
	zval *callback;
	uv_loop_t *loop;
	php_uv_t *uv;
	char *path;
	int path_len;
	long flag, mode;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zsllz", &zloop, &path, &path_len, &flag, &mode, &callback) == FAILURE) {
		return;
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));
	if (!uv) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_queue_work emalloc failed");
		return;
	}
	
	if (zloop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = uv_default_loop();
	}

	uv->type = IS_UV_FS;
	PHP_UV_INIT_ZVALS(uv)

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;
	
	r = uv_fs_open(loop, (uv_fs_t*)&uv->uv.fs, path, flag, mode, php_uv_fs_cb);

	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_async_init failed");
		return;
	}

	TSRMLS_SET_CTX(uv->thread_ctx);
	MAKE_STD_ZVAL(tmp);
	ZEND_REGISTER_RESOURCE(tmp, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(tmp);
	Z_TYPE_P(tmp) = IS_NULL;
	zval_ptr_dtor(&tmp);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_fs_read)
{
	int r;
	zval *tmp, *zloop = NULL;
	zval *callback;
	uv_loop_t *loop;
	php_uv_t *uv;
	unsigned long fd;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zlz", &zloop, &fd, &callback) == FAILURE) {
		return;
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));
	if (!uv) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_queue_work emalloc failed");
		return;
	}
	
	if (zloop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = uv_default_loop();
	}

	uv->type = IS_UV_FS;
	PHP_UV_INIT_ZVALS(uv)

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	//uv_fs_read($loop, int $fd, Closure $cb)
	//UV_EXTERN int uv_fs_read(uv_loop_t* loop, uv_fs_t* req, uv_file file, void* buf, size_t length, off_t offset, uv_fs_cb cb);
	memset(uv_fs_read_buf, 0, sizeof(uv_fs_read_buf));
	r = uv_fs_read(loop, (uv_fs_t*)&uv->uv.fs, fd, uv_fs_read_buf, sizeof(uv_fs_read_buf), -1, php_uv_fs_cb);

	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_async_init failed");
		return;
	}

	TSRMLS_SET_CTX(uv->thread_ctx);
	MAKE_STD_ZVAL(tmp);
	ZEND_REGISTER_RESOURCE(tmp, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(tmp);
	Z_TYPE_P(tmp) = IS_NULL;
	zval_ptr_dtor(&tmp);
}
/* }}} */


//* UV_EXTERN int uv_fs_close(uv_loop_t* loop, uv_fs_t* req, uv_file file,uv_fs_cb cb);
/* {{{ */
PHP_FUNCTION(uv_fs_close)
{
	int r;
	zval *tmp, *zloop = NULL;
	zval *callback;
	uv_loop_t *loop;
	php_uv_t *uv;
	unsigned long fd;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zlz", &zloop, &fd, &callback) == FAILURE) {
		return;
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));
	if (!uv) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_queue_work emalloc failed");
		return;
	}
	
	if (zloop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = uv_default_loop();
	}

	uv->type = IS_UV_FS;
	PHP_UV_INIT_ZVALS(uv)

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	//uv_fs_read($loop, int $fd, Closure $cb)
	//UV_EXTERN int uv_fs_read(uv_loop_t* loop, uv_fs_t* req, uv_file file, void* buf, size_t length, off_t offset, uv_fs_cb cb);
	memset(uv_fs_read_buf, 0, sizeof(uv_fs_read_buf));
	r = uv_fs_close(loop, (uv_fs_t*)&uv->uv.fs, fd, php_uv_fs_cb);

	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_fs_close failed");
		return;
	}

	TSRMLS_SET_CTX(uv->thread_ctx);
	MAKE_STD_ZVAL(tmp);
	ZEND_REGISTER_RESOURCE(tmp, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(tmp);
	Z_TYPE_P(tmp) = IS_NULL;
	zval_ptr_dtor(&tmp);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_fs_write)
{
	int r;
	zval *tmp, *zloop = NULL;
	zval *callback;
	uv_loop_t *loop;
	php_uv_t *uv;
	char *buffer;
	int buffer_len = 0;
	unsigned long fd;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zlsz", &zloop, &fd, &buffer, &buffer_len, &callback) == FAILURE) {
		return;
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));
	if (!uv) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_fs_write emalloc failed");
		return;
	}
	
	if (zloop != NULL) {
		ZEND_FETCH_RESOURCE(loop, uv_loop_t*, &zloop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	} else {
		loop = uv_default_loop();
	}

	uv->type = IS_UV_FS;
	PHP_UV_INIT_ZVALS(uv)

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;
	
	uv->buffer = estrndup(buffer, buffer_len);
	
	//* UV_EXTERN int uv_fs_write(uv_loop_t* loop, uv_fs_t* req, uv_file file,void* buf, size_t length, off_t offset, uv_fs_cb cb);
	r = uv_fs_write(loop, (uv_fs_t*)&uv->uv.fs, fd, uv->buffer, buffer_len, -1, php_uv_fs_cb);

	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_fs_write failed");
		return;
	}

	TSRMLS_SET_CTX(uv->thread_ctx);
	MAKE_STD_ZVAL(tmp);
	ZEND_REGISTER_RESOURCE(tmp, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(tmp);
	Z_TYPE_P(tmp) = IS_NULL;
	zval_ptr_dtor(&tmp);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_fsync)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	unsigned long fd;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zlz", &zloop, &fd, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, fsync, fd);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_fdatasync)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	unsigned long fd;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zlz", &zloop, &fd, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, fdatasync, fd);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_ftruncate)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	long offset = 0;
	unsigned long fd;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zllz", &zloop, &fd, &offset, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, ftruncate, fd, offset);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_mkdir)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	char *path;
	int path_len = 0;
	long mode = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zslz", &zloop, &path, &path_len, &mode, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, mkdir, path, mode);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_fs_rmdir)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	char *path;
	int path_len = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zsz", &zloop, &path, &path_len, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, rmdir, path);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_unlink)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	char *path;
	int path_len = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zsz", &zloop, &path, &path_len, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, unlink, path);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_rename)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	char *from, *to;
	int from_len, to_len = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zssz", &zloop, &from, &from_len, &to, &to_len, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, rename, from, to);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_utime)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	long utime, atime;
	char *path;
	int path_len = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zsllz", &zloop, &path, &path_len, &utime, &atime, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, utime, path, utime, atime);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_futime)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	long utime, atime;
	unsigned long fd;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zlllz", &zloop, &fd, &utime, &atime, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, futime, fd, utime, atime);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_chmod)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	long mode;
	char *path;
	int path_len = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zslz", &zloop, &path, &path_len, &mode, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, chmod, path, mode);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_fs_fchmod)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	long mode;
	unsigned long fd;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zlllz", &zloop, &fd, &mode, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, fchmod, fd, mode);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_fs_chown)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	long uid, gid;
	char *path;
	int path_len = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zslz", &zloop, &path, &path_len, &uid, &gid, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, chown, path, uid, gid);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_fchown)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	long uid, gid;
	unsigned long fd;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zlllz", &zloop, &fd, &uid, &gid, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, fchown, fd, uid, gid);
}
/* }}} */
	
/* {{{ */
PHP_FUNCTION(uv_fs_link)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	char *from, *to;
	int from_len, to_len = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zssz", &zloop, &from, &from_len, &to, &to_len, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, link, from, to);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_fs_symlink)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	char *from, *to;
	int from_len, to_len = 0;
	long flags;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zsslz", &zloop, &from, &from_len, &to, &to_len, &flags, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, symlink, from, to, flags);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_readlink)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	char *path;
	int path_len = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zsz", &zloop, &path, &path_len, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, readlink, path);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_stat)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	char *path;
	int path_len = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zsz", &zloop, &path, &path_len, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, stat, path);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_lstat)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	char *path;
	int path_len = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zsz", &zloop, &path, &path_len, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, lstat, path);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_fstat)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	unsigned long fd;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zlz", &zloop, &fd, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, fstat, fd);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_fs_readdir)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	char *path;
	int path_len = 0;
	long flags;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zslz", &zloop, &path, &path_len, &flags, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, readdir, path, flags);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_sendfile)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	unsigned long in_fd, out_fd;
	long offset, length = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zllllz", &zloop, &in_fd, &out_fd, &offset, &length, &callback) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->fs_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs.data = uv;

	PHP_UV_FS_ASYNC(loop, sendfile, in_fd, out_fd, offset, length);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_fs_event_init)
{
	int error;
	zval *callback, *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	char *path;
	int path_len = 0;
	long flags = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zszl", &zloop, &path, &path_len, &callback, &flags) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_FS_EVENT);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);
	PHP_UV_LIST_INSERT(uv, uv_resource_handle);
	
	uv->fs_event_cb = callback;
	Z_ADDREF_P(callback);
	uv->uv.fs_event.data = uv;

	error = uv_fs_event_init(loop, (uv_fs_event_t*)&uv->uv.fs_event, path, php_uv_fs_event_cb, flags);
	if (error) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_fs_event_init failed"); \
		return;
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_tty_init)
{
	int error;
	zval *zloop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	long readable = 1;
	unsigned long fd;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zll", &zloop, &fd, &readable) == FAILURE) {
		return;
	}

	PHP_UV_INIT_UV(uv, IS_UV_TTY);
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop, zloop);

	uv->uv.tty.data = uv;
	
	error = uv_tty_init(loop, (uv_tty_t*)&uv->uv.tty, fd, readable); \
	if (error) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_fs_event_init failed"); \
		return;
	}
	

	ZVAL_RESOURCE(return_value, uv->resource_id);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_tty_get_winsize)
{
	php_uv_t *uv;
	zval *handle, *w, *h = NULL;
	int error, width, height;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zzz", &handle, &w, &h) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t*, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	error = uv_tty_get_winsize(&uv->uv.tty, &width, &height);
	
	ZVAL_LONG(w, width);
	ZVAL_LONG(h, height);

	RETURN_LONG(error);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_tty_set_mode)
{
	php_uv_t *uv;
	zval *handle;
	long mode;
	long error = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zl", &handle, &mode) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t*, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	error = uv_tty_set_mode(&uv->uv.tty, mode);
	RETURN_LONG(error);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_tty_reset_mode)
{
	uv_tty_reset_mode();
}
/* }}} */

#ifdef PHP_WIN32
/* {{{ */
PHP_FUNCTION(uv_tcp_simultaneous_accepts)
{
	php_uv_t *uv;
	zval *handle, *result;
	long enable;
	long error = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zl", &handle, &enable) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t*, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	error = uv_tcp_simultaneous_accepts(&uv->uv.tcp, enable);
	RETURN_LONG(error);
}
/* }}} */
#endif

/* {{{ */
PHP_FUNCTION(uv_tcp_getsockname)
{
	php_uv_t *uv;
	zval *handle, *result;
	int addr_len, error = 0;
	struct sockaddr_storage addr;
	addr_len = sizeof(struct sockaddr_storage);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t*, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	error  = uv_tcp_getsockname(&uv->uv.tcp, (struct sockaddr*)&addr, &addr_len);
	
	result = php_uv_address_to_zval((struct sockaddr*)&addr);
	RETURN_ZVAL(result, 0, 1);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_tcp_getpeername)
{
	php_uv_t *uv;
	zval *handle, *result;
	int addr_len, error = 0;
	struct sockaddr_storage addr;
	addr_len = sizeof(struct sockaddr_storage);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t*, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	error  = uv_tcp_getpeername(&uv->uv.tcp, (struct sockaddr*)&addr, &addr_len);
	
	result = php_uv_address_to_zval((struct sockaddr*)&addr);
	RETURN_ZVAL(result, 0, 1);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_udp_getsockname)
{
	php_uv_t *uv;
	zval *handle, *result;
	int addr_len, error = 0;
	struct sockaddr_storage addr;
	addr_len = sizeof(struct sockaddr_storage);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t*, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	error  = uv_udp_getsockname(&uv->uv.udp, (struct sockaddr*)&addr, &addr_len);
	
	result = php_uv_address_to_zval((struct sockaddr*)&addr);
	RETURN_ZVAL(result, 0, 1);
}
/* }}} */


/* {{{ */
PHP_FUNCTION(uv_resident_set_memory)
{
	size_t rss;
	uv_resident_set_memory(&rss);

	RETURN_LONG(rss);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_ip4_name)
{
	int error = 0;
	zval *address;
	php_uv_sockaddr_t *addr;
	char ip[INET6_ADDRSTRLEN];
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z",&address) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(addr, php_uv_sockaddr_t *, &address, -1, PHP_UV_SOCKADDR_RESOURCE_NAME, uv_sockaddr_handle);
	
	error = uv_ip4_name(&addr->addr.ipv4, ip, INET6_ADDRSTRLEN);
	RETVAL_STRING(ip,1);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_ip6_name)
{
	int error = 0;
	zval *address;
	php_uv_sockaddr_t *addr;
	char ip[INET6_ADDRSTRLEN];
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z",&address) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(addr, php_uv_sockaddr_t *, &address, -1, PHP_UV_SOCKADDR_RESOURCE_NAME, uv_sockaddr_handle);
	
	error = uv_ip6_name(&addr->addr.ipv6, ip, INET6_ADDRSTRLEN);
	RETVAL_STRING(ip,1);
}
/* }}} */

/* HTTP PARSER */
ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_http_parser_init, 0, 0, 1)
	ZEND_ARG_INFO(0, target)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_http_parser_execute, 0, 0, 3)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, buffer)
	ZEND_ARG_INFO(0, setting)
ZEND_END_ARG_INFO()

PHP_FUNCTION(uv_http_parser_init)
{
	long target = HTTP_REQUEST;
	php_http_parser_context *ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|l",&target) == FAILURE) {
		return;
	}

	ctx = emalloc(sizeof(php_http_parser_context));
	http_parser_init(&ctx->parser, target);

	if (target == HTTP_RESPONSE) {
		ctx->is_response = 1;
	} else {
		ctx->is_response = 0;
	}

	memset(&ctx->handle, 0, sizeof(struct http_parser_url));

	/* setup callback */
	ctx->settings.on_message_begin = on_message_begin;
	ctx->settings.on_header_field = header_field_cb;
	ctx->settings.on_header_value = header_value_cb;
	ctx->settings.on_url = on_url_cb;
	ctx->settings.on_body = on_body_cb;
	ctx->settings.on_headers_complete = on_headers_complete;
	ctx->settings.on_message_complete = on_message_complete;


	ZEND_REGISTER_RESOURCE(return_value, ctx, uv_httpparser_handle);
}

PHP_FUNCTION(uv_http_parser_execute)
{
	zval *z_parser,*result, *headers;
	php_http_parser_context *context;
	char *body;
	int body_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rs/a",&z_parser, &body, &body_len, &result) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(context, php_http_parser_context*, &z_parser, -1, PHP_UV_HTTPPARSER_RESOURCE_NAME, uv_httpparser_handle);

	MAKE_STD_ZVAL(headers);
	array_init(headers);
	add_assoc_zval(result, "headers", headers);

	context->headers = headers;
	context->data = result;
	context->parser.data = context;

	http_parser_execute(&context->parser, &context->settings, body, body_len);

	if (context->is_response == 0) {
		add_assoc_string(result, "REQUEST_METHOD", (char*)http_method_str(context->parser.method), 1);
	} else {
		add_assoc_long(result, "status_code", (long)context->parser.status_code);
	}

	if (context->finished == 1) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}


static zend_function_entry uv_functions[] = {
	/* general */
	PHP_FE(uv_update_time,              arginfo_uv_update_time)
	PHP_FE(uv_ref,                      arginfo_uv_ref)
	PHP_FE(uv_unref,                    arginfo_uv_unref)
	PHP_FE(uv_default_loop,             NULL)
	PHP_FE(uv_run,                      arginfo_uv_run)
	PHP_FE(uv_run_once,                 arginfo_uv_run_once)
	PHP_FE(uv_ip4_addr,                 arginfo_uv_ip4_addr)
	PHP_FE(uv_ip6_addr,                 arginfo_uv_ip6_addr)
	PHP_FE(uv_ip4_name,                 arginfo_uv_ip4_name)
	PHP_FE(uv_ip6_name,                 arginfo_uv_ip6_name)
	PHP_FE(uv_write,                    arginfo_uv_write)
	PHP_FE(uv_shutdown,                 arginfo_uv_shutdown)
	PHP_FE(uv_close,                    arginfo_uv_close)
	PHP_FE(uv_now,                      arginfo_uv_now)
	PHP_FE(uv_loop_delete,              arginfo_uv_loop_delete)
	PHP_FE(uv_read_start,               arginfo_uv_read_start)
	PHP_FE(uv_read2_start,              arginfo_uv_read2_start)
	PHP_FE(uv_read_stop,                arginfo_uv_read_stop)
	PHP_FE(uv_last_error,               arginfo_uv_last_error)
	PHP_FE(uv_err_name,                 arginfo_uv_err_name)
	PHP_FE(uv_strerror,                 arginfo_uv_strerror)
	PHP_FE(uv_is_active,                arginfo_uv_is_active)
	PHP_FE(uv_is_readable,              arginfo_uv_is_readable)
	PHP_FE(uv_is_writable,              arginfo_uv_is_writable)
	/* idle */
	PHP_FE(uv_idle_init,                arginfo_uv_idle_init)
	PHP_FE(uv_idle_start,               arginfo_uv_idle_start)
	PHP_FE(uv_idle_stop,                arginfo_uv_idle_stop)
	/* timer */
	PHP_FE(uv_timer_init,               arginfo_uv_timer_init)
	PHP_FE(uv_timer_start,              arginfo_uv_timer_start)
	PHP_FE(uv_timer_stop,               arginfo_uv_timer_stop)
	PHP_FE(uv_timer_again,              arginfo_uv_timer_again)
	PHP_FE(uv_timer_set_repeat,         arginfo_uv_timer_set_repeat)
	PHP_FE(uv_timer_get_repeat,         arginfo_uv_timer_get_repeat)
	/* tcp */
	PHP_FE(uv_tcp_init,                 arginfo_uv_tcp_init)
	PHP_FE(uv_tcp_nodelay,              arginfo_uv_tcp_nodelay)
	PHP_FE(uv_tcp_bind,                 arginfo_uv_tcp_bind)
	PHP_FE(uv_tcp_bind6,                arginfo_uv_tcp_bind6)
	PHP_FE(uv_listen,                   arginfo_uv_listen)
	PHP_FE(uv_accept,                   arginfo_uv_accept)
	PHP_FE(uv_tcp_connect,              arginfo_uv_tcp_connect)
	PHP_FE(uv_tcp_connect6,             arginfo_uv_tcp_connect6)
	/* udp */
	PHP_FE(uv_udp_init,                 arginfo_uv_udp_init)
	PHP_FE(uv_udp_bind,                 arginfo_uv_udp_bind)
	PHP_FE(uv_udp_bind6,                arginfo_uv_udp_bind6)
	PHP_FE(uv_udp_set_multicast_loop,   arginfo_uv_udp_set_multicast_loop)
	PHP_FE(uv_udp_set_multicast_ttl,    arginfo_uv_udp_set_multicast_ttl)
	PHP_FE(uv_udp_send,                 arginfo_uv_udp_send)
	PHP_FE(uv_udp_recv_start,           arginfo_uv_udp_recv_start)
	PHP_FE(uv_udp_recv_stop,            arginfo_uv_udp_recv_stop)
	PHP_FE(uv_udp_set_membership,       arginfo_uv_udp_set_membership)
	/* other network functions */
	PHP_FE(uv_tcp_getsockname,          arginfo_uv_tcp_getsockname)
	PHP_FE(uv_tcp_getpeername,          arginfo_uv_tcp_getpeername)
	PHP_FE(uv_udp_getsockname,          arginfo_uv_udp_getsockname)
#ifdef PHP_WIN32
	PHP_FE(uv_tcp_simultaneous_accepts, NULL)
#endif
	/* pipe */
	PHP_FE(uv_pipe_init,                arginfo_uv_pipe_init)
	PHP_FE(uv_pipe_bind,                arginfo_uv_pipe_bind)
	PHP_FE(uv_pipe_open,                arginfo_uv_pipe_open)
	PHP_FE(uv_pipe_connect,             arginfo_uv_pipe_connect)
	PHP_FE(uv_pipe_pending_instances,   arginfo_uv_pipe_pending_instances)
	/* spawn */
	PHP_FE(uv_spawn,                    arginfo_uv_spawn)
	PHP_FE(uv_process_kill,             arginfo_uv_process_kill)
	PHP_FE(uv_kill,                     arginfo_uv_kill)
	/* c-ares */
	PHP_FE(uv_getaddrinfo,              arginfo_uv_tcp_connect)
	PHP_FE(uv_ares_init_options,        arginfo_uv_ares_init_options)
	PHP_FE(ares_gethostbyname,          arginfo_ares_gethostbyname)
	/* rwlock */
	PHP_FE(uv_rwlock_init,              NULL)
	PHP_FE(uv_rwlock_rdlock,            arginfo_uv_rwlock_rdlock)
	PHP_FE(uv_rwlock_tryrdlock,         arginfo_uv_rwlock_tryrdlock)
	PHP_FE(uv_rwlock_rdunlock,          arginfo_uv_rwlock_rdunlock)
	PHP_FE(uv_rwlock_wrlock,            arginfo_uv_rwlock_wrlock)
	PHP_FE(uv_rwlock_trywrlock,         arginfo_uv_rwlock_trywrlock)
	PHP_FE(uv_rwlock_wrunlock,          arginfo_uv_rwlock_wrunlock)
	/* mutex */
	PHP_FE(uv_mutex_init,               NULL)
	PHP_FE(uv_mutex_lock,               arginfo_uv_mutex_lock)
	PHP_FE(uv_mutex_trylock,            arginfo_uv_mutex_trylock)
	PHP_FE(uv_mutex_unlock,             arginfo_uv_mutex_unlock)
	/* prepare (before poll hook) */
	PHP_FE(uv_prepare_init,             NULL)
	PHP_FE(uv_prepare_start,            arginfo_uv_prepare_start)
	PHP_FE(uv_prepare_stop,             arginfo_uv_prepare_stop)
	/* check (after poll hook) */
	PHP_FE(uv_check_init,               arginfo_uv_check_init)
	PHP_FE(uv_check_start,              arginfo_uv_check_start)
	PHP_FE(uv_check_stop,               arginfo_uv_check_stop)
	/* async */
	PHP_FE(uv_async_init,               arginfo_uv_async_init)
	PHP_FE(uv_async_send,               arginfo_uv_async_send)
	/* queue (does not work yet) */
	PHP_FE(uv_queue_work,               NULL)
	/* fs */
	PHP_FE(uv_fs_open,                  arginfo_uv_fs_open)
	PHP_FE(uv_fs_read,                  arginfo_uv_fs_read)
	PHP_FE(uv_fs_write,                 arginfo_uv_fs_write)
	PHP_FE(uv_fs_close,                 arginfo_uv_fs_close)
	PHP_FE(uv_fs_fsync,                 arginfo_uv_fs_fsync)
	PHP_FE(uv_fs_fdatasync,             arginfo_uv_fs_ftruncate)
	PHP_FE(uv_fs_ftruncate,             arginfo_uv_fs_ftruncate)
	PHP_FE(uv_fs_mkdir,                 arginfo_uv_fs_mkdir)
	PHP_FE(uv_fs_rmdir,                 arginfo_uv_fs_rmdir)
	PHP_FE(uv_fs_unlink,                arginfo_uv_fs_unlink)
	PHP_FE(uv_fs_rename,                arginfo_uv_fs_rename)
	PHP_FE(uv_fs_utime,                 arginfo_uv_fs_utime)
	PHP_FE(uv_fs_futime,                arginfo_uv_fs_futime)
	PHP_FE(uv_fs_chmod,                 arginfo_uv_fs_chmod)
	PHP_FE(uv_fs_fchmod,                arginfo_uv_fs_fchmod)
	PHP_FE(uv_fs_chown,                 arginfo_uv_fs_chown)
	PHP_FE(uv_fs_fchown,                arginfo_uv_fs_fchown)
	PHP_FE(uv_fs_link,                  arginfo_uv_fs_link)
	PHP_FE(uv_fs_symlink,               arginfo_uv_fs_symlink)
	PHP_FE(uv_fs_readlink,              arginfo_uv_fs_readlink)
	PHP_FE(uv_fs_stat,                  arginfo_uv_fs_stat)
	PHP_FE(uv_fs_lstat,                 arginfo_uv_fs_lstat)
	PHP_FE(uv_fs_fstat,                 arginfo_uv_fs_fstat)
	PHP_FE(uv_fs_readdir,               arginfo_uv_fs_readdir)
	PHP_FE(uv_fs_sendfile,              arginfo_uv_fs_sendfile)
	PHP_FE(uv_fs_event_init,            arginfo_uv_fs_event_init)
	/* tty */
	PHP_FE(uv_tty_init,                 arginfo_uv_tty_init)
	PHP_FE(uv_tty_get_winsize,          arginfo_uv_tty_get_winsize)
	PHP_FE(uv_tty_set_mode,             NULL)
	PHP_FE(uv_tty_reset_mode,           NULL)
	/* info */
	PHP_FE(uv_loadavg,                  NULL)
	PHP_FE(uv_uptime,                   NULL)
	PHP_FE(uv_cpu_info,                 NULL)
	PHP_FE(uv_interface_addresses,      NULL)
	PHP_FE(uv_get_free_memory,          NULL)
	PHP_FE(uv_get_total_memory,         NULL)
	PHP_FE(uv_hrtime,                   NULL)
	PHP_FE(uv_exepath,                  NULL)
	PHP_FE(uv_cwd,                      NULL)
	PHP_FE(uv_chdir,                    arginfo_uv_chdir)
	PHP_FE(uv_resident_set_memory,      NULL)
	/* http parser */
	PHP_FE(uv_http_parser_init,          arginfo_uv_http_parser_init)
	PHP_FE(uv_http_parser_execute,       arginfo_uv_http_parser_execute)
	{NULL, NULL, NULL}
};


PHP_MINFO_FUNCTION(uv)
{
	char uv_version[20];
	sprintf(uv_version, "%d.%d",UV_VERSION_MAJOR, UV_VERSION_MINOR);
	
	php_printf("PHP libuv Extension\n");
	php_info_print_table_start();
	php_info_print_table_header(2,"libuv Support",  "enabled");
	php_info_print_table_row(2,"Version", PHP_UV_EXTVER);
	php_info_print_table_row(2,"bundled libuv Version", uv_version);
	php_info_print_table_end();
}

zend_module_entry uv_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"uv",
	uv_functions,					/* Functions */
	PHP_MINIT(uv),	/* MINIT */
	NULL,					/* MSHUTDOWN */
	NULL,					/* RINIT */
	PHP_RSHUTDOWN(uv),		/* RSHUTDOWN */
	PHP_MINFO(uv),	/* MINFO */
#if ZEND_MODULE_API_NO >= 20010901
	PHP_UV_EXTVER,
#endif
	STANDARD_MODULE_PROPERTIES
};


#ifdef COMPILE_DL_UV
ZEND_GET_MODULE(uv)
#endif

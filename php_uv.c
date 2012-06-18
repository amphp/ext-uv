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

#ifndef PHP_UV_DEBUG
#define PHP_UV_DEBUG 1
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


#define PHP_UV_INIT_ZVALS(uv) \
	{ \
		uv->address     = NULL; \
		uv->listen_cb   = NULL; \
		uv->read_cb     = NULL; \
		uv->write_cb    = NULL; \
		uv->close_cb    = NULL; \
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
	}

/* static variables */

static uv_loop_t *_php_uv_default_loop;

/* resources */

static int uv_resource_handle;

static int uv_ares_handle;

static int uv_loop_handle;

static int uv_sockaddr_handle;

static int uv_rwlock_handle;

static int uv_mutex_handle;

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

static uv_buf_t php_uv_read_alloc(uv_handle_t* handle, size_t suggested_size);

static void php_uv_close_cb(uv_handle_t *handle);

static void php_uv_timer_cb(uv_timer_t *handle, int status);

static void php_uv_idle_cb(uv_timer_t *handle, int status);

/* destructor */

void static destruct_uv_mutex(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	uv_mutex_t *mutex = (uv_mutex_t *)rsrc->ptr;
	uv_mutex_destroy(mutex);
	efree(mutex);
}


void static destruct_uv_rwlock(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	uv_rwlock_t *rwlock = (uv_rwlock_t *)rsrc->ptr;
	uv_rwlock_destroy(rwlock);
	efree(rwlock);
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
#if PHP_UV_DEBUG>=1
	fprintf(stderr,"# will be free: (resource_id: %d)", obj->resource_id);
#endif

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
	php_uv_t *obj = (php_uv_t *)rsrc->ptr;
#if PHP_UV_DEBUG>=1
	fprintf(stderr,"# will be free: (resource_id: %d)", obj->resource_id);
#endif

	if (obj->in_free) {
		/* TODO: why other php_uv_t has already set this? */
		//fprintf(stderr, "resource_id: %d is freeing", obj->resource_id);
		//return;
	}
	
	obj->in_free = 1;
	if (obj->address) {
		//fprintf(stderr, "address: %d\n", Z_REFCOUNT_P(obj->read_cb));
		zval_ptr_dtor(&obj->address);
		obj->address = NULL;
	}
	if (obj->read_cb) {
		//fprintf(stderr, "readcb: %d\n", Z_REFCOUNT_P(obj->read_cb));
		zval_ptr_dtor(&obj->read_cb);
		obj->read_cb = NULL;
	}
	if (obj->write_cb) {
		//fprintf(stderr, "writecb: %d\n", Z_REFCOUNT_P(obj->write_cb));
		zval_ptr_dtor(&obj->write_cb);
		obj->write_cb = NULL;
	}
	if (obj->close_cb) {
		//fprintf(stderr, "closecb: %d\n", Z_REFCOUNT_P(obj->close_cb));
		zval_ptr_dtor(&obj->close_cb);
		obj->close_cb = NULL;
	}
	if (obj->listen_cb) {
		//fprintf(stderr, "listen_cb: %d\n", Z_REFCOUNT_P(obj->listen_cb));
		zval_ptr_dtor(&obj->listen_cb);
		obj->listen_cb = NULL;
	}
	if (obj->idle_cb) {
		//fprintf(stderr, "idle_cb: %d\n", Z_REFCOUNT_P(obj->listen_cb));
		zval_ptr_dtor(&obj->idle_cb);
		obj->idle_cb = NULL;
	}
	if (obj->connect_cb) {
		//fprintf(stderr, "connect_cb: %d\n", Z_REFCOUNT_P(obj->listen_cb));
		zval_ptr_dtor(&obj->connect_cb);
		obj->connect_cb = NULL;
	}
	if (obj->udp_recv_cb) {
		//fprintf(stderr, "udp_recv_cb: %d\n", Z_REFCOUNT_P(obj->listen_cb));
		zval_ptr_dtor(&obj->udp_recv_cb);
		obj->udp_recv_cb = NULL;
	}
	if (obj->udp_send_cb) {
		//fprintf(stderr, "udp_send_cb: %d\n", Z_REFCOUNT_P(obj->listen_cb));
		zval_ptr_dtor(&obj->udp_send_cb);
		obj->udp_send_cb = NULL;
	}
	if (obj->pipe_connect_cb) {
		//fprintf(stderr, "udp_send_cb: %d\n", Z_REFCOUNT_P(obj->listen_cb));
		zval_ptr_dtor(&obj->pipe_connect_cb);
		obj->pipe_connect_cb = NULL;
	}
	if (obj->proc_close_cb) {
		//fprintf(stderr, "uv_spawn: %d\n", Z_REFCOUNT_P(obj->proc_close_cb));
		zval_ptr_dtor(&obj->proc_close_cb);
		obj->proc_close_cb = NULL;
	}
	if (obj->prepare_cb) {
		//fprintf(stderr, "uv_prepare: %d\n", Z_REFCOUNT_P(obj->prepare_cb));
		zval_ptr_dtor(&obj->prepare_cb);
		obj->prepare_cb = NULL;
	}
	if (obj->check_cb) {
		//fprintf(stderr, "uv_prepare: %d\n", Z_REFCOUNT_P(obj->prepare_cb));
		zval_ptr_dtor(&obj->check_cb);
		obj->check_cb = NULL;
	}
	if (obj->async_cb) {
		//fprintf(stderr, "uv_async: %d\n", Z_REFCOUNT_P(obj->async_cb));
		zval_ptr_dtor(&obj->async_cb);
		obj->async_cb = NULL;
	}
	if (obj->work_cb) {
		//fprintf(stderr, "uv_async: %d\n", Z_REFCOUNT_P(obj->async_cb));
		zval_ptr_dtor(&obj->work_cb);
		obj->work_cb = NULL;
	}
	if (obj->after_work_cb) {
		//fprintf(stderr, "uv_async: %d\n", Z_REFCOUNT_P(obj->async_cb));
		zval_ptr_dtor(&obj->after_work_cb);
		obj->after_work_cb = NULL;
	}

	if (obj->resource_id) {
		base_id = obj->resource_id;
		obj->resource_id = 0;
	}

	if (obj != NULL) {
		efree(obj);
		obj = NULL;
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

	params[0] = &stat;
	params[1] = &client;
	
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

#if PHP_UV_DEBUG>=1
	fprintf(stderr,"status: %d\n", status);
#endif
	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);
	
	MAKE_STD_ZVAL(client);
	ZVAL_RESOURCE(client, uv->resource_id);
	//zend_list_addref(uv->resource_id);

	params[0] = &stat;
	params[1] = &client;
	
	php_uv_do_callback(&retval_ptr, uv->write_cb, params, 2 TSRMLS_CC);

	zval_ptr_dtor(&retval_ptr);
	zval_ptr_dtor(&stat);
	zval_ptr_dtor(&client);

	if (wr->buf.base) {
		//free(wr->buf.base);
	}
	efree(wr);
#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_write_cb del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find (write_cb)");
		}
	}
#endif
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

	params[0] = &stat;
	params[1] = &client;
	
	php_uv_do_callback(&retval_ptr, uv->udp_send_cb, params, 2 TSRMLS_CC);

	zval_ptr_dtor(&retval_ptr);
	zval_ptr_dtor(&stat);
	zval_ptr_dtor(&client);

	if (wr->buf.base) {
		efree(wr->buf.base);
	}
	efree(wr);
}


static void php_uv_listen_cb(uv_stream_t* server, int status)
{
	zval *retval_ptr, *svr= NULL;
	zval **params[1];
	php_uv_t *uv = (php_uv_t*)server->data;

	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	MAKE_STD_ZVAL(svr);
	ZVAL_RESOURCE(svr, uv->resource_id);
	zend_list_addref(uv->resource_id);

	params[0] = &svr;

	php_uv_do_callback(&retval_ptr, uv->listen_cb, params, 1 TSRMLS_CC);
	
	zval_ptr_dtor(&retval_ptr);
	zval_ptr_dtor(&svr);
}

static void php_uv_close_cb2(uv_handle_t *handle)
{
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);
#if PHP_UV_DEBUG>=1
	fprintf(stderr,"closecb2");
#endif
	zend_list_delete(uv->resource_id);
}

static void php_uv_shutdown_cb(uv_shutdown_t* req, int status)
{
	uv_close((uv_handle_t*)req->handle, php_uv_close_cb2);
	efree(req);
}

static void php_uv_read_cb(uv_stream_t* handle, ssize_t nread, uv_buf_t buf)
{
	zval *retval_ptr = NULL;
	zval **params[2];
	zval *buffer;
	zval *rsc;
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

#if PHP_UV_DEBUG>=1
	fprintf(stderr,"read_cb");
#endif

	if (nread < 0) {
		/* does this should be in user-land ? */
		//uv_shutdown_t* req;
		
		/* Error or EOF */
		assert(uv_last_error(uv_default_loop()).code == UV_EOF);
		//zend_list_delete(uv->resource_id);
		if (buf.base) {
			efree(buf.base);
		}
		
		//req = (uv_shutdown_t*) emalloc(sizeof *req);
#if PHP_UV_DEBUG>=1
		fprintf(stderr,"read close");
#endif
		uv_close(handle, php_uv_close_cb2);
		return;
	}
	
	if (nread == 0) {
		/* Everything OK, but nothing read. */
		efree(buf.base);
		return;
	}
	

	MAKE_STD_ZVAL(buffer);
	ZVAL_STRINGL(buffer,buf.base,nread, 1);

	MAKE_STD_ZVAL(rsc);
	ZVAL_RESOURCE(rsc, uv->resource_id);
	//zend_list_addref(uv->resource_id);

	params[0] = &buffer;
	params[1] = &rsc;
	
	php_uv_do_callback(&retval_ptr, uv->read_cb, params, 2 TSRMLS_CC);

	zval_ptr_dtor(&buffer);
	zval_ptr_dtor(&rsc);
	zval_ptr_dtor(&retval_ptr);

	if (buf.base) {
		efree(buf.base);
	}
#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_read_cb del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find (read_cb)");
		}
	}
#endif
}

static void php_uv_prepare_cb(uv_stream_t* handle, int status)
{
	zval *retval_ptr = NULL;
	zval **params[1];
	zval *zstat;
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

#if PHP_UV_DEBUG>=1
	fprintf(stderr,"prepare_cb");
#endif

	MAKE_STD_ZVAL(zstat);
	ZVAL_LONG(zstat, status);

	params[0] = &zstat;
	
	php_uv_do_callback(&retval_ptr, uv->prepare_cb, params, 1 TSRMLS_CC);

	zval_ptr_dtor(&zstat);
	zval_ptr_dtor(&retval_ptr);

#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_prepare_cb del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find (prepare_cb)");
		}
	}
#endif
}

static void php_uv_check_cb(uv_stream_t* handle, int status)
{
	zval *retval_ptr = NULL;
	zval **params[1];
	zval *zstat;
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

#if PHP_UV_DEBUG>=1
	fprintf(stderr,"check_cb");
#endif

	MAKE_STD_ZVAL(zstat);
	ZVAL_LONG(zstat, status);

	params[0] = &zstat;
	
	php_uv_do_callback(&retval_ptr, uv->check_cb, params, 1 TSRMLS_CC);

	zval_ptr_dtor(&zstat);
	zval_ptr_dtor(&retval_ptr);

#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_check_cb del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find (check_cb)");
		}
	}
#endif
}


static void php_uv_async_cb(uv_stream_t* handle, int status)
{
	zval *retval_ptr = NULL;
	zval **params[1];
	zval *zstat;
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

#if PHP_UV_DEBUG>=1
	fprintf(stderr,"async_cb");
#endif

	MAKE_STD_ZVAL(zstat);
	ZVAL_LONG(zstat, status);

	params[0] = &zstat;
	
	php_uv_do_callback(&retval_ptr, uv->async_cb, params, 1 TSRMLS_CC);

	zval_ptr_dtor(&zstat);
	zval_ptr_dtor(&retval_ptr);

#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_async_cb del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find (async_cb)");
		}
	}
#endif
}


static void php_uv_work_cb(uv_work_t* req)
{
	zval *retval_ptr = NULL;
	php_uv_t *uv = (uv_work_t*)req->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

#if PHP_UV_DEBUG>=1
	fprintf(stderr,"work_cb");
#endif

	php_uv_do_callback(&retval_ptr, uv->work_cb, NULL, 0 TSRMLS_CC);
	zval_ptr_dtor(&retval_ptr);

#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_work_cb del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find (work_cb)");
		}
	}
#endif
}

static void php_uv_after_work_cb(uv_work_t* req)
{
	zval *retval_ptr = NULL;
	php_uv_t *uv = (php_uv_t*)req->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

#if PHP_UV_DEBUG>=1
	fprintf(stderr,"after_work_cb");
#endif

	php_uv_do_callback(&retval_ptr, uv->after_work_cb, NULL, 0 TSRMLS_CC);
	zval_ptr_dtor(&retval_ptr);

#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_after_work_cb del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find (work_cb)");
		}
	}
#endif
}

static void php_uv_udp_recv_cb(uv_udp_t* handle, ssize_t nread, uv_buf_t buf, struct sockaddr* addr, unsigned flags)
{
	/* TODO: is this implment correct? */
	zval *retval_ptr = NULL;
	zval **params[2];
	zval *buffer;
	zval *rsc;
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);
	
	if (nread < 0) {
		/* does this should be in user-land ? */
		uv_shutdown_t* req;
		
		/* Error or EOF */
		assert(uv_last_error(uv_default_loop()).code == UV_EOF);
		
		if (buf.base) {
			efree(buf.base);
		}
		
		req = (uv_shutdown_t*) emalloc(sizeof *req);
		uv_shutdown(req, (uv_stream_t*)handle, php_uv_shutdown_cb);
		return;
	}
	
	if (nread == 0) {
		/* Everything OK, but nothing read. */
		efree(buf.base);
		return;
	}
	
	MAKE_STD_ZVAL(buffer);
	ZVAL_STRINGL(buffer,buf.base,nread, 1);

	MAKE_STD_ZVAL(rsc);
	ZVAL_RESOURCE(rsc, uv->resource_id);

	params[0] = &buffer;
	params[1] = &rsc;
	
	php_uv_do_callback(&retval_ptr, uv->udp_recv_cb, params, 2 TSRMLS_CC);

	zval_ptr_dtor(&buffer);
	zval_ptr_dtor(&rsc);
	zval_ptr_dtor(&retval_ptr);

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
		zval_ptr_dtor(&retval_ptr);
	}
#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_close_cb del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find (close_cb)");
		}
	}
#endif
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

	zval_ptr_dtor(&retval_ptr);
	zval_ptr_dtor(&stat);
}

static void php_uv_getaddrinfo_cb(uv_getaddrinfo_t* handle, int status, struct addrinfo* res)
{
	/* TODO */
	efree(handle);
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

	zval_ptr_dtor(&retval_ptr);
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
		default: {
			TSRMLS_FETCH();
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "unexpected type found");
			break;
		}
	}
	
	return stream;
}


/* zend */

PHP_MINIT_FUNCTION(uv) {
	int rc;

	php_uv_init(TSRMLS_C);
	uv_resource_handle = zend_register_list_destructors_ex(destruct_uv, NULL, PHP_UV_RESOURCE_NAME, module_number);
	uv_ares_handle  = zend_register_list_destructors_ex(destruct_uv_ares, NULL, PHP_UV_ARES_RESOURCE_NAME, module_number);
	uv_loop_handle = zend_register_list_destructors_ex(destruct_uv_loop, NULL, PHP_UV_LOOP_RESOURCE_NAME, module_number);
	uv_sockaddr_handle = zend_register_list_destructors_ex(destruct_uv_sockaddr, NULL, PHP_UV_SOCKADDR_RESOURCE_NAME, module_number);
	uv_rwlock_handle = zend_register_list_destructors_ex(destruct_uv_rwlock, NULL, PHP_UV_RWLOCK_RESOURCE_NAME, module_number);
	uv_mutex_handle = zend_register_list_destructors_ex(destruct_uv_mutex, NULL, PHP_UV_MUTEX_RESOURCE_NAME, module_number);

	rc = ares_library_init(ARES_LIB_INIT_ALL);
	if (rc != 0) {
		printf("ares library init fails %d\n", rc);
		return FAILURE;
	}

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
	ZEND_ARG_INFO(0, port)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_close, 0, 0, 1)
	ZEND_ARG_INFO(0, stream)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_ares_gethostbyname, 0, 0, 2)
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

/* PHP Functions */

/* {{{ */
PHP_FUNCTION(uv_unref)
{
	zval *z_loop = NULL;
	uv_loop_t *loop;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z",&z_loop) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	uv_unref(loop);
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
	zval *z_loop = NULL;
	uv_loop_t *loop;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z",&z_loop) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	uv_ref(loop);
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
	Z_ADDREF_P(resource);
	
	r = uv_tcp_bind((uv_tcp_t*)&uv->uv.tcp, addr->addr.ipv4);
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
	php_uv_t *client;
	write_req_t *w;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zsz",&z_cli, &data, &data_len,&callback) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(client, php_uv_t *, &z_cli, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	Z_ADDREF_P(callback);
	client->write_cb = callback;
	zend_list_addref(client->resource_id);

	w = emalloc(sizeof(write_req_t));
	w->req.data = client;
	w->buf = uv_buf_init(data, data_len);

	uv_write(&w->req, (uv_stream_t*)php_uv_get_current_stream(client), &w->buf, 1, php_uv_write_cb);
#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), client->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_write del(%d): %d->%d\n", client->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find (uv_write)");
		}
	}
#endif
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

#if PHP_UV_DEBUG>=1
	fprintf(stderr,"uv_read_start");
#endif

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
#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uvread_start del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find(uv_read_start)");
		}
	}
#endif

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
#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_read_stop del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find(uv_read_stop)");
		}
	}
#endif

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
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "listen failed");
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
	uv->uv.timer.data = uv;
	PHP_UV_INIT_ZVALS(uv)
	
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
	zval *z_loop, *callback = NULL;
	uv_loop_t *loop;
	php_uv_t *uv = NULL;
	uv_getaddrinfo_t *handle = (uv_getaddrinfo_t*)emalloc(sizeof(uv_getaddrinfo_t));

	/* FIXME: hints */
	char *node, *service, *hints;
	int node_len, service_len, hints_len = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
	"zzsss",&z_loop, &callback, &node, &node_len, &service, &service_len, &hints, &hints_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	Z_ADDREF_P(callback);

	uv->getaddr_cb = callback;
	uv_getaddrinfo(loop, handle, php_uv_getaddrinfo_cb, node, service, NULL);
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
	zval *zloop;
	uv_loop_t *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|z",&loop) == FAILURE) {
		return;
	}
	if (loop) {
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
	/*uv_loop_t *loop;  TODO */
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

	uv->type = IS_UV_PIPE;
	r = uv_pipe_init(uv_default_loop(), &uv->uv.pipe, ipc);
	
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
	int name_len = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zs",&handle, &name, &name_len) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &handle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	uv_pipe_bind(&uv->uv.pipe, name);
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

static void aresbyaddrcallback( void *arg,
                          int status,
                          int timeouts,
                          struct hostent *hostent) {
	int * iargs;
	iargs = (int*)arg;
	printf("aresbyaddrcallback %d\n",1);
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


/* {{{ */
PHP_FUNCTION(ares_test)
{
/*
struct ares_options {
  int flags;
  int timeout; // in seconds or milliseconds, depending on options
  int tries;
  int ndots;
  unsigned short udp_port;
  unsigned short tcp_port;
  int socket_send_buffer_size;
  int socket_receive_buffer_size;
  struct in_addr *servers;
  int nservers;
  char **domains;
  int ndomains;
  char *lookups;
  ares_sock_state_cb sock_state_cb;
  void *sock_state_cb_data;
  struct apattern *sortlist;
  int nsort;
};
*/
	int rc;
	ares_channel channel;
	struct ares_options options;
	int optmask;
//char *domains[1] = {"/ets/hosts"};
	int bynamecallbacksig;

/*
struct sockaddr_in {
    short   sin_family;
    u_short sin_port;
    struct  in_addr sin_addr;
    char    sin_zero[8];
};
*/

	struct sockaddr_in test_server = uv_ip4_addr("8.8.8.8", 53);
	optmask = ARES_OPT_SERVERS | ARES_OPT_TCP_PORT | ARES_OPT_LOOKUPS | ARES_OPT_FLAGS;

	options.servers = &test_server.sin_addr;
	options.nservers = 1;
	options.tcp_port = test_server.sin_port;
	options.lookups = "b";
	options.flags = ARES_FLAG_USEVC;
	rc = uv_ares_init_options(uv_default_loop(), &channel, &options, optmask);
	bynamecallbacksig = 7;

	ares_gethostbyname(channel,
		"chobie.net",
		AF_INET,
		&php_ares_gethostbyname_cb,
		&bynamecallbacksig
	);
	uv_run(uv_default_loop());

}
/* }}} */

/* {{{ */
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

/* {{{ */
PHP_FUNCTION(uv_uptime)
{
	zval *retval;
	uv_err_t error;
	double uptime;

	error = uv_uptime(&uptime);
	
	MAKE_STD_ZVAL(retval);
	ZVAL_DOUBLE(retval, uptime);

	RETURN_ZVAL(retval,0,1);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_get_process_title)
{
	char buffer[512] = {0};
	uv_err_t error;

	/* TODO: check behavior */
	error = uv_get_process_title(buffer,sizeof(buffer));
	if (UV_OK == error.code) {
		RETURN_STRING(buffer,1);
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_get_free_memory)
{
	RETURN_LONG(uv_get_free_memory());
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_get_total_memory)
{
	RETURN_LONG(uv_get_total_memory());
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_hrtime)
{
	/* TODO: check behavior */
	RETURN_LONG(uv_hrtime());
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_exepath)
{
	char buffer[1024] = {0};
	size_t buffer_sz = sizeof(buffer);
	
	/* TODO: check behavior */
	uv_exepath(buffer, &buffer_sz);
	buffer[buffer_sz] = '\0';
	
	RETURN_STRINGL(buffer, buffer_sz, 1);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_cwd)
{
	char buffer[1024] = {0};
	size_t buffer_sz = sizeof(buffer);
	
	/* TODO: check behavior */
	uv_cwd(buffer, &buffer_sz);
	buffer[buffer_sz] = '\0';
	
	RETURN_STRINGL(buffer, buffer_sz, 1);
}
/* }}} */

/* {{{ */
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
			array_init(tmp);
			MAKE_STD_ZVAL(times);
			array_init(times);

			add_assoc_string_ex(tmp, "model", sizeof("model"), cpus[i].model, 1);
			add_assoc_long_ex(tmp,   "speed", sizeof("speed"), cpus[i].speed);

			add_assoc_long_ex(times, "sys", sizeof("sys"), (size_t)cpus[i].cpu_times.sys);
			add_assoc_long_ex(times, "user", sizeof("user"), (size_t)cpus[i].cpu_times.user);
			add_assoc_long_ex(times, "idle", sizeof("idle"), (size_t)cpus[i].cpu_times.idle);
			add_assoc_long_ex(times, "irq", sizeof("irq"), (size_t)cpus[i].cpu_times.irq);
			add_assoc_long_ex(times, "nice", sizeof("nice"), (size_t)cpus[i].cpu_times.nice);
			add_assoc_zval_ex(tmp,"times", sizeof("times"), times);

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
	php_uv_t *proc;

	zval *args, *context, *callback;
	char **zenv;
	char *command;
	char **command_args;
	int command_len = 0;

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
			int i = 0;
			
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
					options.stdout_stream = &pipe->uv.pipe;
				} else if (pos->h == 1) {
					options.stdin_stream = &pipe->uv.pipe;
				} else if (pos->h == 2) {
					options.stderr_stream = &pipe->uv.pipe;
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
	uv_rwlock_t *lock;
	int error;
	
	lock = emalloc(sizeof(uv_rwlock_t));
	error = uv_rwlock_init(lock);
	if (error == 0) {
		ZEND_REGISTER_RESOURCE(return_value, lock, uv_rwlock_handle);
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_rwlock_rdlock)
{
	uv_rwlock_t *lock;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(lock, uv_rwlock_t *, &handle, -1, PHP_UV_RWLOCK_RESOURCE_NAME, uv_rwlock_handle);
	uv_rwlock_rdlock(lock);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_rwlock_tryrdlock)
{
	uv_rwlock_t *lock;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(lock, uv_rwlock_t *, &handle, -1, PHP_UV_RWLOCK_RESOURCE_NAME, uv_rwlock_handle);
	RETURN_LONG(uv_rwlock_tryrdlock(lock));
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_rwlock_rdunlock)
{
	uv_rwlock_t *lock;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(lock, uv_rwlock_t *, &handle, -1, PHP_UV_RWLOCK_RESOURCE_NAME, uv_rwlock_handle);
	uv_rwlock_rdunlock(lock);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_rwlock_wrlock)
{
	uv_rwlock_t *lock;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(lock, uv_rwlock_t *, &handle, -1, PHP_UV_RWLOCK_RESOURCE_NAME, uv_rwlock_handle);
	uv_rwlock_wrlock(lock);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_rwlock_trywrlock)
{
	uv_rwlock_t *lock;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(lock, uv_rwlock_t *, &handle, -1, PHP_UV_RWLOCK_RESOURCE_NAME, uv_rwlock_handle);
	RETURN_LONG(uv_rwlock_trywrlock(lock));
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_rwlock_wrunlock)
{
	uv_rwlock_t *lock;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(lock, uv_rwlock_t *, &handle, -1, PHP_UV_RWLOCK_RESOURCE_NAME, uv_rwlock_handle);
	uv_rwlock_wrunlock(lock);
}
/* }}} */



/* {{{ */
PHP_FUNCTION(uv_mutex_init)
{
	uv_mutex_t *mutex;
	int error;
	
	mutex = emalloc(sizeof(uv_mutex_t));
	error = uv_mutex_init(mutex);
	if (error == 0) {
		ZEND_REGISTER_RESOURCE(return_value, mutex, uv_mutex_handle);
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_mutex_lock)
{
	uv_mutex_t *mutex;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(mutex, uv_mutex_t *, &handle, -1, PHP_UV_MUTEX_RESOURCE_NAME, uv_mutex_handle);
	uv_mutex_lock(mutex);
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_mutex_trylock)
{
	uv_mutex_t *mutex;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(mutex, uv_mutex_t *, &handle, -1, PHP_UV_MUTEX_RESOURCE_NAME, uv_mutex_handle);
	RETURN_LONG(uv_mutex_trylock(mutex));
}
/* }}} */

/* {{{ */
PHP_FUNCTION(uv_mutex_unlock)
{
	uv_mutex_t *mutex;
	zval *handle;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z", &handle) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(mutex, uv_mutex_t *, &handle, -1, PHP_UV_MUTEX_RESOURCE_NAME, uv_mutex_handle);
	uv_mutex_unlock(mutex);
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

#if PHP_UV_DEBUG>=1
	fprintf(stderr,"uv_prepare_start");
#endif

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

	r = uv_prepare_start((uv_stream_t*)php_uv_get_current_stream(uv), php_uv_prepare_cb);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "read failed");
	}
#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_prepare_start del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find(uv_prepare_start)");
		}
	}
#endif

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
	uv_prepare_stop((uv_stream_t*)php_uv_get_current_stream(uv));
#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_prepare_stop del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find(uv_prepare_stop)");
		}
	}
#endif

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

#if PHP_UV_DEBUG>=1
	fprintf(stderr,"uv_check_start");
#endif

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

	r = uv_check_start((uv_stream_t*)php_uv_get_current_stream(uv), php_uv_check_cb);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "read failed");
	}
#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_check_start del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find(uv_check_start)");
		}
	}
#endif

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
	uv_check_stop((uv_stream_t*)php_uv_get_current_stream(uv));
#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_check_stop del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find(uv_check_stop)");
		}
	}
#endif

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
	uv_async_send((uv_stream_t*)php_uv_get_current_stream(uv));
#if PHP_UV_DEBUG>=1
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("# uv_async_send del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
		} else {
			printf("# can't find(uv_async_send)");
		}
	}
#endif

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

static zend_function_entry uv_functions[] = {
	/* general */
	PHP_FE(uv_update_time, arginfo_uv_update_time)
	PHP_FE(uv_ref, arginfo_uv_ref)
	PHP_FE(uv_unref, arginfo_uv_unref)
	PHP_FE(uv_default_loop, NULL)
	PHP_FE(uv_run, arginfo_uv_run)
	PHP_FE(uv_run_once, arginfo_uv_run_once)
	PHP_FE(uv_ip4_addr, arginfo_uv_ip4_addr)
	PHP_FE(uv_write, arginfo_uv_write)
	PHP_FE(uv_close, arginfo_uv_close)
	PHP_FE(uv_now, arginfo_uv_now)
	PHP_FE(uv_loop_delete, arginfo_uv_loop_delete)
	PHP_FE(uv_read_start, arginfo_uv_read_start)
	PHP_FE(uv_read_stop, arginfo_uv_read_stop)
	PHP_FE(uv_last_error, arginfo_uv_last_error)
	PHP_FE(uv_err_name, arginfo_uv_err_name)
	PHP_FE(uv_strerror, arginfo_uv_strerror)
	PHP_FE(uv_is_active, arginfo_uv_is_active)
	PHP_FE(uv_is_readable, arginfo_uv_is_readable)
	PHP_FE(uv_is_writable, arginfo_uv_is_writable)
	/* idle */
	PHP_FE(uv_idle_init, arginfo_uv_idle_init)
	PHP_FE(uv_idle_start, arginfo_uv_idle_start)
	PHP_FE(uv_idle_stop, arginfo_uv_idle_stop)
	/* timer */
	PHP_FE(uv_timer_init, arginfo_uv_timer_init)
	PHP_FE(uv_timer_start, arginfo_uv_timer_start)
	PHP_FE(uv_timer_stop, arginfo_uv_timer_stop)
	PHP_FE(uv_timer_again, arginfo_uv_timer_again)
	PHP_FE(uv_timer_set_repeat, arginfo_uv_timer_set_repeat)
	PHP_FE(uv_timer_get_repeat, arginfo_uv_timer_get_repeat)
	/* tcp */
	PHP_FE(uv_tcp_init, arginfo_uv_tcp_init)
	PHP_FE(uv_tcp_nodelay, arginfo_uv_tcp_nodelay)
	PHP_FE(uv_tcp_bind, arginfo_uv_tcp_bind)
	PHP_FE(uv_listen, arginfo_uv_listen)
	PHP_FE(uv_accept, arginfo_uv_accept)
	PHP_FE(uv_tcp_connect, arginfo_uv_tcp_connect)
	/* udp */
	PHP_FE(uv_udp_init, arginfo_uv_udp_init)
	PHP_FE(uv_udp_bind, arginfo_uv_udp_bind)
	PHP_FE(uv_udp_set_multicast_loop, arginfo_uv_udp_set_multicast_loop)
	PHP_FE(uv_udp_set_multicast_ttl, arginfo_uv_udp_set_multicast_ttl)
	PHP_FE(uv_udp_send, arginfo_uv_udp_send)
	PHP_FE(uv_udp_recv_start, arginfo_uv_udp_recv_start)
	PHP_FE(uv_udp_recv_stop, arginfo_uv_udp_recv_stop)
	/* pipe */
	PHP_FE(uv_pipe_init, arginfo_uv_pipe_init)
	PHP_FE(uv_pipe_bind, arginfo_uv_pipe_bind)
	PHP_FE(uv_pipe_open, arginfo_uv_pipe_open)
	PHP_FE(uv_pipe_connect, arginfo_uv_pipe_connect)
	PHP_FE(uv_pipe_pending_instances, arginfo_uv_pipe_pending_instances)
	/* spawn */
	PHP_FE(uv_spawn, arginfo_uv_spawn)
	PHP_FE(uv_process_kill, arginfo_uv_process_kill)
	PHP_FE(uv_kill, arginfo_uv_kill)
	/* c-ares */
	PHP_FE(uv_getaddrinfo, arginfo_uv_tcp_connect)
	PHP_FE(uv_ares_init_options, NULL)
	PHP_FE(ares_gethostbyname, NULL)
	PHP_FE(ares_test, NULL)
	/* PHP_FE(ares_gethostbyname, arginfo_ares_gethostbyname) */
	/* rwlock */
	PHP_FE(uv_rwlock_init, NULL)
	PHP_FE(uv_rwlock_rdlock, NULL)
	PHP_FE(uv_rwlock_tryrdlock, NULL)
	PHP_FE(uv_rwlock_rdunlock, NULL)
	PHP_FE(uv_rwlock_wrlock, NULL)
	PHP_FE(uv_rwlock_trywrlock, NULL)
	PHP_FE(uv_rwlock_wrunlock, NULL)
	/* mutex */
	PHP_FE(uv_mutex_init, NULL)
	PHP_FE(uv_mutex_lock, NULL)
	PHP_FE(uv_mutex_trylock, NULL)
	PHP_FE(uv_mutex_unlock, NULL)
	/* prepare (before poll hook) */
	PHP_FE(uv_prepare_init, NULL)
	PHP_FE(uv_prepare_start, NULL)
	PHP_FE(uv_prepare_stop, NULL)
	/* check (after poll hook) */
	PHP_FE(uv_check_init, NULL)
	PHP_FE(uv_check_start, NULL)
	PHP_FE(uv_check_stop, NULL)
	/* async */
	PHP_FE(uv_async_init, NULL)
	PHP_FE(uv_async_send, NULL)
	/* queue */
	PHP_FE(uv_queue_work, NULL)
	/* info */
	PHP_FE(uv_loadavg, NULL)
	PHP_FE(uv_uptime, NULL)
	PHP_FE(uv_get_process_title, NULL)
	PHP_FE(uv_cpu_info, NULL)
	PHP_FE(uv_interface_addresses, NULL)
	PHP_FE(uv_get_free_memory, NULL)
	PHP_FE(uv_get_total_memory, NULL)
	PHP_FE(uv_hrtime, NULL)
	PHP_FE(uv_exepath, NULL)
	PHP_FE(uv_cwd, NULL)
	PHP_FE(uv_chdir, arginfo_uv_chdir)
	{NULL, NULL, NULL}
};


PHP_MINFO_FUNCTION(uv)
{
	php_printf("PHP libuv Extension\n");
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
	NULL,					/* RSHUTDOWN */
	PHP_MINFO(uv),	/* MINFO */
#if ZEND_MODULE_API_NO >= 20010901
	PHP_UV_EXTVER,
#endif
	STANDARD_MODULE_PROPERTIES
};


#ifdef COMPILE_DL_UV
ZEND_GET_MODULE(uv)
#endif

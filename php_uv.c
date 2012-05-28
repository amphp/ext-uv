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

extern void php_uv_init(TSRMLS_D);
extern zend_class_entry *uv_class_entry;

typedef struct {
	uv_write_t req;
	uv_buf_t buf;
} write_req_t;

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
	}

/* static variables */

static uv_loop_t *_php_uv_default_loop;


/* resources */

static int uv_resource_handle;

static int uv_connect_handle;

static int uv_loop_handle;

static int uv_sockaddr_handle;


/* declarations */

void php_uv_init(TSRMLS_D);

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

void static destruct_uv_loop(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	uv_loop_t *loop = (php_uv_t *)rsrc->ptr;
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


void static destruct_uv(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	int base_id = -1;
	//fprintf(stderr, "will be free\n");
	php_uv_t *obj = (php_uv_t *)rsrc->ptr;
	
	if (obj->in_free) {
		/* TODO: why other php_uv_t has already set this? */
		//fprintf(stderr, "resource_id: %d is freeing", obj->resource_id);
		//return;
	}
	
	obj->in_free = 1;
	if (obj->address) {
		//fprintf(stderr, "readcb: %d\n", Z_REFCOUNT_P(obj->read_cb));
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
		//fprintf(stderr, "listencb: %d\n", Z_REFCOUNT_P(obj->listen_cb));
		zval_ptr_dtor(&obj->listen_cb);
		obj->listen_cb = NULL;
	}
	if (obj->idle_cb) {
		//fprintf(stderr, "listencb: %d\n", Z_REFCOUNT_P(obj->listen_cb));
		zval_ptr_dtor(&obj->idle_cb);
		obj->idle_cb = NULL;
	}
	if (obj->connect_cb) {
		//fprintf(stderr, "listencb: %d\n", Z_REFCOUNT_P(obj->listen_cb));
		zval_ptr_dtor(&obj->connect_cb);
		obj->connect_cb = NULL;
	}

	if (obj->resource_id) {
		base_id = obj->resource_id;
		obj->resource_id = NULL;
	}

	if (obj != NULL) {
		efree(obj);
		obj = NULL;
	}
	
	if (base_id) {
		/* basically, this block always fail */
		zend_list_delete(base_id);
	}

}

/* callback */


static void php_uv_tcp_connect_cb(uv_connect_t *req, int status)
{
	TSRMLS_FETCH();
	zval *retval_ptr, *stat, *client= NULL;
	zval **params[2];
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;
	char *is_callable_error = NULL;

	php_uv_t *uv = (php_uv_t*)req->data;
	
	if(zend_fcall_info_init(uv->connect_cb, 0, &fci,&fcc,NULL,&is_callable_error TSRMLS_CC) == SUCCESS) {
		if (is_callable_error) {
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "to be a valid callback");
		}
	}
	
	fci.retval_ptr_ptr = &retval_ptr;

	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);
	
	MAKE_STD_ZVAL(client);
	ZVAL_RESOURCE(client, uv->resource_id);
	zend_list_addref(uv->resource_id);

	params[0] = &stat;
	params[1] = &client;
	
	fci.params = params;
	fci.param_count = 2;
	
	zend_call_function(&fci, &fcc TSRMLS_CC);
	zval_ptr_dtor(&retval_ptr);
	zval_ptr_dtor(&stat);
	zval_ptr_dtor(&client);
	efree(req);
}

static void php_uv_write_cb(uv_write_t* req, int status)
{
	TSRMLS_FETCH();
	write_req_t* wr;
	zval *retval_ptr, *stat, *client= NULL;
	zval **params[2];
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;
	char *is_callable_error = NULL;

	wr = (write_req_t*) req;
	php_uv_t *uv = (php_uv_t*)req->data;
	
	if(zend_fcall_info_init(uv->write_cb, 0, &fci,&fcc,NULL,&is_callable_error TSRMLS_CC) == SUCCESS) {
		if (is_callable_error) {
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "to be a valid callback");
		}
	}
	
	/* for now */
	fci.retval_ptr_ptr = &retval_ptr;

	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);
	
	MAKE_STD_ZVAL(client);
	ZVAL_RESOURCE(client, uv->resource_id);
	zend_list_addref(uv->resource_id);

	params[0] = &stat;
	params[1] = &client;
	
	fci.params = params;
	fci.param_count = 2;
	
	zend_call_function(&fci, &fcc TSRMLS_CC);
	zval_ptr_dtor(&retval_ptr);
	zval_ptr_dtor(&stat);
	zval_ptr_dtor(&client);

	if (wr->buf.base) {
		//free(wr->buf.base);
	}
	efree(wr);
}

static void php_uv_listen_cb(uv_stream_t* server, int status)
{
	TSRMLS_FETCH();
	zval *retval_ptr, *svr= NULL;
	zval **params[1];
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;
	char *is_callable_error = NULL;

	php_uv_t *uv = (php_uv_t*)server->data;
	
	if(zend_fcall_info_init(uv->listen_cb, 0, &fci,&fcc,NULL,&is_callable_error TSRMLS_CC) == SUCCESS) {
		if (is_callable_error) {
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "to be a valid callback");
		}
	}
	
	/* for now */
	fci.retval_ptr_ptr = &retval_ptr;

	MAKE_STD_ZVAL(svr);
	ZVAL_RESOURCE(svr, uv->resource_id);
	zend_list_addref(uv->resource_id);

	params[0] = &svr;
	
	fci.params = params;
	fci.param_count = 1;
	
	zend_call_function(&fci, &fcc TSRMLS_CC);
	zval_ptr_dtor(&retval_ptr);
	zval_ptr_dtor(&svr);
}

static void php_uv_close_cb2(uv_handle_t *handle)
{
	/* what should I do here? */
}

static void php_uv_shutdown_cb(uv_shutdown_t* req, int status)
{
	uv_close((uv_handle_t*)req->handle, php_uv_close_cb2);
	efree(req);
}

static void php_uv_read_cb(uv_stream_t* handle, ssize_t nread, uv_buf_t buf)
{
	TSRMLS_FETCH();
	zval *retval_ptr = NULL;
	zval **params[2];
	zval *buffer;
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;
	char *is_callable_error = NULL;
	
	if (nread < 0) {
		uv_shutdown_t* req;
		
		/* Error or EOF */
		assert(uv_last_error(uv_default_loop()).code == UV_EOF);
		
		if (buf.base) {
			efree(buf.base);
		}
		
		req = (uv_shutdown_t*) emalloc(sizeof *req);
		uv_shutdown(req, handle, php_uv_shutdown_cb);
		return;
	}
	
	if (nread == 0) {
		/* Everything OK, but nothing read. */
		efree(buf.base);
		return;
	}
	
	php_uv_t *uv = (php_uv_t*)handle->data;
	if(zend_fcall_info_init(uv->read_cb, 0, &fci, &fcc, NULL, &is_callable_error TSRMLS_CC) == SUCCESS) {
		if (is_callable_error) {
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "to be a valid callback");
		}
	}
	
	// for now
	fci.retval_ptr_ptr = &retval_ptr;

	MAKE_STD_ZVAL(buffer);
	ZVAL_STRINGL(buffer,buf.base,nread, 1);

	zval *rsc;
	MAKE_STD_ZVAL(rsc);
	ZVAL_RESOURCE(rsc, uv->resource_id);
	//zend_list_addref(uv->resource_id);

	params[0] = &buffer;
	params[1] = &rsc;
	
	fci.params = params;
	fci.param_count = 2;
	
	//zend_fcall_info_args(&fci, *params TSRMLS_CC);
	zend_call_function(&fci, &fcc TSRMLS_CC);
	//zend_fcall_info_args_clear(&fcc, 1);
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
	TSRMLS_FETCH();
	zval *retval_ptr = NULL;
	zval **params[1];
	zval *h;
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;
	char *is_callable_error = NULL;

	php_uv_t *uv = (php_uv_t*)handle->data;
	if(zend_fcall_info_init(uv->close_cb, 0, &fci, &fcc, NULL, &is_callable_error TSRMLS_CC) == SUCCESS) {
		if (is_callable_error) {
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "to be a valid callback");
		}
	}
	
	// for now
	fci.retval_ptr_ptr = &retval_ptr;

	MAKE_STD_ZVAL(h);
	ZVAL_RESOURCE(h, uv->resource_id);

	params[0] = &h;
	
	fci.params = params;
	fci.param_count = 1;
	
	//zend_fcall_info_args(&fci, *params TSRMLS_CC);
	zend_call_function(&fci, &fcc TSRMLS_CC);
	//zend_fcall_info_args_clear(&fcc, 1);
	zval_ptr_dtor(&retval_ptr);
	/* for testing resource ref count.
	{
		zend_rsrc_list_entry *le;
		if (zend_hash_index_find(&EG(regular_list), uv->resource_id, (void **) &le)==SUCCESS) {
			printf("del(%d): %d->%d\n", uv->resource_id, le->refcount, le->refcount-1);
			zend_list_delete(uv->resource_id);
		} else {
			printf("can't find");
		}
	}
	*/
	zval_ptr_dtor(&h); /* call destruct_uv */
}


static void php_uv_idle_cb(uv_timer_t *handle, int status)
{
	TSRMLS_FETCH();
	zval *retval_ptr, *stat = NULL;
	zval **params[1];
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;
	char *is_callable_error = NULL;

	php_uv_t *uv = (php_uv_t*)handle->data;
	
	if(zend_fcall_info_init(uv->idle_cb, 0, &fci,&fcc,NULL,&is_callable_error TSRMLS_CC) == SUCCESS) {
		if (is_callable_error) {
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "to be a valid callback");
		}
	}
	
	/* for now */
	fci.retval_ptr_ptr = &retval_ptr;

	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);

	params[0] = &stat;
	
	fci.params = params;
	fci.param_count = 1;
	
	zend_call_function(&fci, &fcc TSRMLS_CC);

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
	TSRMLS_FETCH();
	zval *retval_ptr, *stat, *client= NULL;
	zval **params[2];
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;
	char *is_callable_error = NULL;

	php_uv_t *uv = (php_uv_t*)handle->data;
	
	if(zend_fcall_info_init(uv->timer_cb, 0, &fci,&fcc,NULL,&is_callable_error TSRMLS_CC) == SUCCESS) {
		if (is_callable_error) {
			php_error_docref(NULL TSRMLS_CC, E_ERROR, "to be a valid callback");
		}
	}
	
	/* for now */
	fci.retval_ptr_ptr = &retval_ptr;

	MAKE_STD_ZVAL(stat);
	ZVAL_LONG(stat, status);
	MAKE_STD_ZVAL(client);
	ZVAL_RESOURCE(client, uv->resource_id);
	zend_list_addref(uv->resource_id);

	params[0] = &stat;
	params[1] = &client;
	
	fci.params = params;
	fci.param_count = 2;
	
	zend_call_function(&fci, &fcc TSRMLS_CC);

	zval_ptr_dtor(&retval_ptr);
	zval_ptr_dtor(&stat);
	zval_ptr_dtor(&client);
}

/* zend */

PHP_MINIT_FUNCTION(uv) {
	php_uv_init(TSRMLS_C);
	uv_resource_handle = zend_register_list_destructors_ex(destruct_uv, NULL, PHP_UV_RESOURCE_NAME, module_number);
	uv_connect_handle  = zend_register_list_destructors_ex(destruct_uv, NULL, PHP_UV_CONNECT_RESOURCE_NAME, module_number);
	uv_loop_handle = zend_register_list_destructors_ex(destruct_uv_loop, NULL, PHP_UV_LOOP_RESOURCE_NAME, module_number);
	uv_sockaddr_handle = zend_register_list_destructors_ex(destruct_uv_sockaddr, NULL, PHP_UV_SOCKADDR_RESOURCE_NAME, module_number);

	return SUCCESS;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_run_once, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_run, 0, 0, 1)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_write, 0, 0, 2)
	ZEND_ARG_INFO(0, client)
	ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_last_error, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_init, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_idle_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, idle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_start, 0, 0, 4)
	ZEND_ARG_INFO(0, timer)
	ZEND_ARG_INFO(0, timeout)
	ZEND_ARG_INFO(0, repeat)
	ZEND_ARG_INFO(0, callback)
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_loop_refcount, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
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


/* PHP Functions */


PHP_FUNCTION(uv_unref)
{
	zval *z_loop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z",&z_loop) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	uv_unref(loop);
}

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

PHP_FUNCTION(uv_ref)
{
	zval *z_loop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z",&z_loop) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	uv_ref(loop);
}

PHP_FUNCTION(uv_loop_refcount)
{
	zval *z_loop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"z",&z_loop) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(loop, uv_loop_t *, &z_loop, -1, PHP_UV_LOOP_RESOURCE_NAME, uv_loop_handle);
	
	RETURN_LONG(uv_loop_refcount(loop));
}

PHP_FUNCTION(uv_run)
{
	zval *z_loop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	
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

PHP_FUNCTION(uv_run_once)
{
	zval *z_loop = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
	
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

PHP_FUNCTION(uv_tcp_bind)
{
	zval *resource;
	char *address;
	int address_len;
	long port = 8080;
	struct sockaddr_in addr;
	php_uv_t *uv;
	int r;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zsl",&resource, &address, &address_len, &port) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &resource, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	addr = uv_ip4_addr(address, port);
	
	r = uv_tcp_bind((uv_tcp_t*)&uv->uv.tcp, addr);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "bind failed");
	}
}

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
	zend_list_addref(client->resource_id);
	Z_ADDREF_P(callback);
	client->write_cb = callback;

	w = emalloc(sizeof(write_req_t));
	w->req.data = client;
	w->buf = uv_buf_init(data, data_len);
	uv_write(&w->req, &client->uv.tcp, &w->buf, 1, php_uv_write_cb);
}

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
	uv_tcp_nodelay(client, bval);
}

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
	
	r = uv_accept((uv_stream_t *)&server->uv.tcp, (uv_stream_t *)&client->uv.tcp);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "accept");
	}
}

PHP_FUNCTION(uv_close)
{
	zval *client, *callback;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rz",&client, &callback) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &client, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	Z_ADDREF_P(callback);

	uv->close_cb = callback;
	uv_close((uv_stream_t*)&uv->uv.tcp, php_uv_close_cb);
}

PHP_FUNCTION(uv_read_start)
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

	uv->read_cb = callback;
	uv->uv.tcp.data = uv;

	r = uv_read_start((uv_stream_t*)&uv->uv.tcp, php_uv_read_alloc, php_uv_read_cb);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "read failed");
	}
}

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
	zend_list_addref(uv->resource_id);

	r = uv_listen((uv_stream_t*)&uv->uv.tcp, backlog, php_uv_listen_cb);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "listen failed");
	}
}

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
	Z_ADDREF_P(callback);
	Z_ADDREF_P(address);
	
	req = (uv_connect_t*)emalloc(sizeof(uv_connect_t));
	
	req->data = uv;
	uv->address = address;
	uv->connect_cb = callback;
	uv_tcp_connect(req, &uv->uv.tcp, addr->addr.ipv4, php_uv_tcp_connect_cb);
}

PHP_FUNCTION(uv_timer_init)
{
	int r;
	/* TODO */
	zval *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|z",&loop) == FAILURE) {
		return;
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));

	r = uv_timer_init(uv_default_loop(), &uv->uv.timer);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_timer_init failed");
		return;
	}
	uv->uv.timer.data = uv;
	PHP_UV_INIT_ZVALS(uv)
	
	ZEND_REGISTER_RESOURCE(return_value, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(return_value);
}

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

	uv->timer_cb = callback;
	uv_timer_start((uv_timer_t*)&uv->uv.timer, php_uv_timer_cb, timeout, repeat);
}

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

	uv->idle_cb = callback;
	uv_idle_start((uv_timer_t*)&uv->uv.idle, php_uv_idle_cb);
}

PHP_FUNCTION(uv_getaddrinfo)
{
	zval *z_loop, *callback = NULL;
	uv_loop_t *loop;
	php_uv_t *uv;
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

PHP_FUNCTION(uv_idle_stop)
{
	zval *idle;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"r", &idle) == FAILURE) {
		return;
	}
	/* probably this doesn't need */ 
	//zend_list_delete(uv->resource_id);

	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &idle, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	uv_idle_stop((uv_timer_t*)&uv->uv.idle);
}

PHP_FUNCTION(uv_tcp_init)
{
	int r;
	/* TODO */
	zval *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|z",&loop) == FAILURE) {
		return;
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));
	if (!uv) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_tcp_init emalloc failed");
		return;
	}

	r = uv_tcp_init(uv_default_loop(), &uv->uv.tcp);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_tcp_init failed");
		return;
	}
	
	uv->uv.tcp.data = uv;
	PHP_UV_INIT_ZVALS(uv)
	
	ZEND_REGISTER_RESOURCE(return_value, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(return_value);
}

PHP_FUNCTION(uv_idle_init)
{
	int r;
	/* TODO */
	zval *loop;
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|z",&loop) == FAILURE) {
		return;
	}

	uv = (php_uv_t *)emalloc(sizeof(php_uv_t));

	r = uv_idle_init(uv_default_loop(), &uv->uv.idle);
	if (r) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "uv_idle_init failed");
		return;
	}
	uv->uv.timer.data = uv;
	PHP_UV_INIT_ZVALS(uv)
	
	ZEND_REGISTER_RESOURCE(return_value, uv, uv_resource_handle);
	uv->resource_id = Z_LVAL_P(return_value);
}

PHP_FUNCTION(uv_default_loop)
{
	ZEND_REGISTER_RESOURCE(return_value, php_uv_default_loop(), uv_loop_handle);
}

static zend_function_entry uv_functions[] = {
	/* general */
	PHP_FE(uv_ref, arginfo_uv_ref)
	PHP_FE(uv_unref, arginfo_uv_unref)
	PHP_FE(uv_default_loop, NULL)
	PHP_FE(uv_run, arginfo_uv_run)
	PHP_FE(uv_run_once, arginfo_uv_run_once)
	PHP_FE(uv_ip4_addr, arginfo_uv_ip4_addr)
	PHP_FE(uv_write, arginfo_uv_write)
	PHP_FE(uv_close, arginfo_uv_close)
	PHP_FE(uv_read_start, arginfo_uv_read_start)
	PHP_FE(uv_last_error, arginfo_uv_last_error)
	/* idle */
	PHP_FE(uv_idle_init, arginfo_uv_idle_init)
	PHP_FE(uv_idle_start, arginfo_uv_idle_start)
	PHP_FE(uv_idle_stop, arginfo_uv_idle_stop)
	/* timer */
	PHP_FE(uv_timer_init, arginfo_uv_timer_init)
	PHP_FE(uv_timer_start, arginfo_uv_timer_start)
	/* tcp */
	PHP_FE(uv_tcp_init, arginfo_uv_tcp_init)
	PHP_FE(uv_tcp_nodelay, arginfo_uv_tcp_nodelay)
	PHP_FE(uv_tcp_bind, arginfo_uv_tcp_bind)
	PHP_FE(uv_listen, arginfo_uv_listen)
	PHP_FE(uv_accept, arginfo_uv_accept)
	PHP_FE(uv_tcp_connect, arginfo_uv_tcp_connect)
	/* for debug */
	PHP_FE(uv_loop_refcount, arginfo_uv_loop_refcount)
	/* c-ares */
	PHP_FE(uv_getaddrinfo, arginfo_uv_tcp_connect)
	/* PHP_FE(ares_gethostbyname, arginfo_ares_gethostbyname) */
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

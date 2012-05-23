/*
   +----------------------------------------------------------------------+
   | PHP Version 5                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2011 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Shuhei Tanuma <chobieee@gmail.com>                          |
   +----------------------------------------------------------------------+
 */


#include "php_uv.h"

extern void php_uv_init(TSRMLS_D);
extern zend_class_entry *uv_class_entry;

static int uv_resource_handle;

void php_uv_init(TSRMLS_D);

static 

void static destruct_uv(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	php_uv_t *obj = (php_uv_t *)rsrc->ptr;
	
	// todo
	//if (Z_TYPE_P(cons->car) == IS_RESOURCE) {
	//	zend_list_delete(Z_RESVAL_P(cons->car));
//}

	efree(obj);
}


PHP_MINIT_FUNCTION(uv) {
	php_uv_init(TSRMLS_C);
	uv_resource_handle = zend_register_list_destructors_ex(destruct_uv, NULL, PHP_UV_RESOURCE_NAME, module_number);

	return SUCCESS;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_run, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_connect, 0, 0, 2)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_init, 0, 0, 1)
	ZEND_ARG_INFO(0, addrress)
	ZEND_ARG_INFO(0, port)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()


PHP_FUNCTION(uv_run)
{
	uv_run(uv_default_loop());
}

static void php_uv_tcp_connect_cb(uv_connect_t *conn_req, int status)
{
	fprintf(stderr,"hello");
}

PHP_FUNCTION(uv_tcp_connect)
{
	zval *resource;
	php_uv_t *uv;
	zend_fcall_info fci = {
		0,NULL,NULL,NULL,NULL,0,NULL,NULL
	};
	zend_fcall_info_cache fci_cache;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"zf",&resource,&fci,&fci_cache) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(uv, php_uv_t *, &resource, -1, PHP_UV_RESOURCE_NAME, uv_resource_handle);
	uv_tcp_connect(&uv->connect, &uv->socket, uv->addr, php_uv_tcp_connect_cb);
}

PHP_FUNCTION(uv_tcp_init)
{
	char *address;
	int address_len;
	long port;
	zval *loop;
	
	php_uv_t *uv;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"s|l|z",&address, &address_len, &port, &loop) == FAILURE) {
		return;
	}
	
	uv = ecalloc(1,sizeof(php_uv_t));
	uv->addr = uv_ip4_addr(address,port);
	uv_tcp_init(uv_default_loop(),&uv->socket);
	
	ZEND_REGISTER_RESOURCE(return_value, uv, uv_resource_handle);
}

static zend_function_entry uv_functions[] = {
	PHP_FE(uv_run, arginfo_uv_run)
	PHP_FE(uv_tcp_init, arginfo_uv_tcp_init)
	PHP_FE(uv_tcp_connect, arginfo_uv_tcp_connect)
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

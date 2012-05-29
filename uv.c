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

void php_uv_init(TSRMLS_D);
zend_class_entry *uv_class_entry;

/* TODO: will be add soon */
static zend_function_entry php_uv_methods[] = {
	{NULL, NULL, NULL}
};

static int php_uv_class_init(TSRMLS_D)
{
	zend_class_entry ce;
	INIT_CLASS_ENTRY(ce, "UV", php_uv_methods);
	uv_class_entry = zend_register_internal_class(&ce TSRMLS_CC);
	//uv_class_entry->create_object = php_uv_new;

	return 0;
}

void php_uv_init(TSRMLS_D)
{
	php_uv_class_init(TSRMLS_C);
}

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
#include <fcntl.h>

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

	zend_declare_class_constant_long(uv_class_entry, "O_RDONLY",  sizeof("O_RDONLY")-1, O_RDONLY TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "O_WRONLY", sizeof("O_WRONLY")-1, O_WRONLY TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "O_RDWR",    sizeof("O_RDWR")-1,   O_RDWR TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "O_CREAT",   sizeof("O_CREAT")-1,  O_CREAT TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "O_EXCL",    sizeof("O_EXCL")-1,   O_EXCL TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "O_TRUNC",   sizeof("O_TRUNC")-1,  O_TRUNC TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "O_APPEND",  sizeof("O_APPEND")-1, O_APPEND TSRMLS_CC);

	zend_declare_class_constant_long(uv_class_entry, "S_IRWXU",  sizeof("S_IRWXU")-1, S_IRWXU TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IRUSR",  sizeof("S_IRUSR")-1, S_IRUSR TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IRWXG",  sizeof("S_IRWXG")-1, S_IRWXG TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IRGRP",  sizeof("S_IRGRP")-1, S_IRWXG TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IWGRP",  sizeof("S_IWGRP")-1, S_IWGRP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IXGRP",  sizeof("S_IXGRP")-1, S_IXGRP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IRWXO",  sizeof("S_IRWXO")-1, S_IRWXO TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IROTH",  sizeof("S_IROTH")-1, S_IROTH TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IWOTH",  sizeof("S_IWOTH")-1, S_IWOTH TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IXOTH",  sizeof("S_IXOTH")-1, S_IXOTH TSRMLS_CC);

	return 0;
}

void php_uv_init(TSRMLS_D)
{
	php_uv_class_init(TSRMLS_C);
}

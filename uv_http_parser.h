#ifndef UV_HTTPPARSER_H
#define UV_HTTPPARSER_H

#include "php.h"
#include "zend_exceptions.h"

#include "http_parser.h"

typedef struct {
	struct http_parser parser;
	struct http_parser_url handle;
	struct http_parser_settings settings;
	int is_response;
	int was_header_value;
	int finished;
	zval *data;
	zval *headers;
	char *tmp;
	size_t tmp_len;
} php_http_parser_context;

#define PHP_UV_HTTPPARSER_RESOURCE_NAME "uv_httpparser"

void register_httpparser(int module_number);

/* HTTP PARSER */
ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_http_parser_init, 0, 0, 1)
    ZEND_ARG_INFO(0, target)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_http_parser_execute, 0, 0, 3)
    ZEND_ARG_INFO(0, resource)
    ZEND_ARG_INFO(0, buffer)
    ZEND_ARG_INFO(0, setting)
ZEND_END_ARG_INFO()

PHP_FUNCTION(uv_http_parser_init);
PHP_FUNCTION(uv_http_parser_execute);

#endif

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


static int uv_httpparser_handle;

void static destruct_httpparser(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	php_http_parser_context *obj = (php_http_parser_context *)rsrc->ptr;
	
	if (obj->headers) {
		zval_ptr_dtor(&obj->headers);
	}
	if (obj->data) {
		zval_ptr_dtor(&obj->data);
	}

	efree(obj);
}

/*  http parser callbacks */
static int on_message_begin(http_parser *p)
{
	return 0;
}

static int on_headers_complete(http_parser *p)
{
	return 0;
}

static int on_message_complete(http_parser *p)
{
	php_http_parser_context *result = p->data;
	result->finished = 1;

	if (result->tmp != NULL) {
		efree(result->tmp);
		result->tmp = NULL;
		result->tmp_len = 0;
	}

	return 0;
}

#define PHP_HTTP_PARSER_PARSE_URL(flag, name) \
	if (result->handle.field_set & (1 << flag)) { \
		const char *tmp_name = at+result->handle.field_data[flag].off; \
		int length = result->handle.field_data[flag].len; \
		add_assoc_stringl(data, #name, (char*)tmp_name, length, 1); \
	} 

static int on_url_cb(http_parser *p, const char *at, size_t len)
{
	php_http_parser_context *result = p->data;
	zval *data = result->data;

	http_parser_parse_url(at, len, 0, &result->handle);
	add_assoc_stringl(data, "QUERY_STRING", (char*)at, len, 1);

	PHP_HTTP_PARSER_PARSE_URL(UF_SCHEMA, SCHEME);
	PHP_HTTP_PARSER_PARSE_URL(UF_HOST, HOST);
	PHP_HTTP_PARSER_PARSE_URL(UF_PORT, PORT);
	PHP_HTTP_PARSER_PARSE_URL(UF_PATH, PATH);
	PHP_HTTP_PARSER_PARSE_URL(UF_QUERY, QUERY);
	PHP_HTTP_PARSER_PARSE_URL(UF_FRAGMENT, FRAGMENT);

	return 0;
}

static int on_status_cb(http_parser *p, const char *at, size_t len)
{
	return 0;
}

char *php_uv_strtoupper(char *s, size_t len)
{
	unsigned char *c, *e;

	c = (unsigned char *)s;
	e = (unsigned char *)c+len;

	while (c < e) {
		*c = toupper(*c);
		if (*c == '-') *c = '_';
		c++;
	}
	return s;
}


static int header_field_cb(http_parser *p, const char *at, size_t len)
{
	php_http_parser_context *result = p->data;

	if (result->was_header_value) {
		if (result->tmp != NULL) {
			efree(result->tmp);
			result->tmp = NULL;
			result->tmp_len = 0;
		}
		result->tmp = estrndup(at, len);
		php_uv_strtoupper(result->tmp, len);
		result->tmp_len = len;
	} else {
		result->tmp = erealloc(result->tmp, len + result->tmp_len + 1);
		memcpy(result->tmp + result->tmp_len, at, len);
		result->tmp[result->tmp_len + len] = '\0';
		result->tmp_len = result->tmp_len + len;
	}

	result->was_header_value = 0;
	return 0;
}

static int header_value_cb(http_parser *p, const char *at, size_t len)
{
	php_http_parser_context *result = p->data;
	zval *data = result->headers;

	if (result->was_header_value) {
		zval **element;

		if (zend_hash_find(Z_ARRVAL_P(data), result->tmp, result->tmp_len+1, (void **)&element) == SUCCESS) {
			Z_STRVAL_PP(element) = erealloc(Z_STRVAL_PP(element), Z_STRLEN_PP(element) + len + 1);
			memcpy(Z_STRVAL_PP(element) + Z_STRLEN_PP(element), at, len);

			Z_STRVAL_PP(element)[Z_STRLEN_PP(element)+len] = '\0';
			Z_STRLEN_PP(element) = Z_STRLEN_PP(element) + len;
		}
	} else {
		add_assoc_stringl(data, result->tmp, (char*)at, len, 1);
	}

	result->was_header_value = 1;
	return 0;
}

static int on_body_cb(http_parser *p, const char *at, size_t len)
{
	php_http_parser_context *result = p->data;
	zval *data = result->headers;

	add_assoc_stringl(data, "BODY", (char*)at, len,  1);

	return 0;
}
/* end of callback */

/* HTTP PARSER */
ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_http_parser_init, 0, 0, 1)
	ZEND_ARG_INFO(0, target)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_http_parser_execute, 0, 0, 3)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, buffer)
	ZEND_ARG_INFO(0, setting)
ZEND_END_ARG_INFO()

/* {{{ proto resource uv_http_parser_init(long $target = UV::HTTP_REQUEST)
*/
PHP_FUNCTION(uv_http_parser_init)
{
	long target = HTTP_REQUEST;
	zval *header, *result;
	php_http_parser_context *ctx = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|l",&target) == FAILURE) {
		return;
	}

	ctx = emalloc(sizeof(php_http_parser_context));
	http_parser_init(&ctx->parser, target);

	MAKE_STD_ZVAL(header);
	array_init(header);
	
	MAKE_STD_ZVAL(result);
	array_init(result);

	ctx->data = result;
	ctx->headers = header;
	ctx->finished = 0;
	ctx->was_header_value = 1;
	ctx->tmp = NULL;
	ctx->tmp_len = 0;

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
	ctx->settings.on_status = on_status_cb;
	ctx->settings.on_body = on_body_cb;
	ctx->settings.on_headers_complete = on_headers_complete;
	ctx->settings.on_message_complete = on_message_complete;

	ZEND_REGISTER_RESOURCE(return_value, ctx, uv_httpparser_handle);
}

/* {{{ proto bool uv_http_parser_execute(resource $parser, string $body, array &$result)
*/
PHP_FUNCTION(uv_http_parser_execute)
{
	zval *z_parser = NULL, *result = NULL, *version = NULL, *headers = NULL;
	php_http_parser_context *context;
	char *body;
	int body_len;
	char version_buffer[4] = {0};
	size_t nparsed = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rs/a",&z_parser, &body, &body_len, &result) == FAILURE) {
		return;
	}
	
	ZEND_FETCH_RESOURCE(context, php_http_parser_context*, &z_parser, -1, PHP_UV_HTTPPARSER_RESOURCE_NAME, uv_httpparser_handle);

	if (context->finished == 1) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "passed uv_parser resource has already finished.");
		RETURN_FALSE;
	}

	context->parser.data = context;
	nparsed = http_parser_execute(&context->parser, &context->settings, body, body_len);

	if (result) {
		zval_dtor(result);
	}

	if (nparsed != body_len) {
		zend_throw_exception_ex(zend_exception_get_default(TSRMLS_C), 0 TSRMLS_CC, "parse failed");
		return;
	}

	ZVAL_ZVAL(result, context->data, 1, 0);
	if (context->is_response == 0) {
		add_assoc_string(result, "REQUEST_METHOD", (char*)http_method_str(context->parser.method), 1);
	} else {
		add_assoc_long(result, "STATUS_CODE", (long)context->parser.status_code);
	}
	add_assoc_long(result, "UPGRADE", (long)context->parser.upgrade);

	MAKE_STD_ZVAL(version);
	snprintf(version_buffer, 4, "%d.%d", context->parser.http_major, context->parser.http_minor);
	ZVAL_STRING(version, version_buffer, 1);

	MAKE_STD_ZVAL(headers);
	ZVAL_ZVAL(headers, context->headers, 1, 0);
	add_assoc_zval(headers, "VERSION", version);
	add_assoc_zval(result, "HEADERS", headers);

	if (context->finished == 1) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}

// static zend_function_entry uv_functions[] = {

	/* http parser */
	PHP_FE(uv_http_parser_init,          arginfo_uv_http_parser_init)
	PHP_FE(uv_http_parser_execute,       arginfo_uv_http_parser_execute)

// php_uv_class_init

	zend_declare_class_constant_long(uv_class_entry,  "HTTP_BOTH", sizeof("HTTP_BOTH")-1, HTTP_BOTH TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "HTTP_REQUEST", sizeof("HTTP_REQUEST")-1, HTTP_REQUEST TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "HTTP_RESPONSE", sizeof("HTTP_RESPONSE")-1, HTTP_RESPONSE TSRMLS_CC);


#ifndef PHP_UV_H

#define PHP_UV_H

#define PHP_UV_EXTNAME "uv"
#define PHP_UV_EXTVER "0.1"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "uv.h"

#include "ext/spl/spl_exceptions.h"
#include "zend_interfaces.h"

/* Define the entry point symbol
 * Zend will use when loading this module
 */
extern zend_module_entry uv_module_entry;
#define phpext_uv_ptr &uv_module_entry;

extern zend_class_entry *uv_class_entry;

typedef struct {
	int in_free;
	int resource_id;
	union {
		uv_tcp_t tcp;
		uv_udp_t udp;
		uv_pipe_t pipe;
		uv_idle_t idle;
		uv_timer_t timer;
		uv_async_t async;
		uv_loop_t loop;
		uv_handle_t handle;
		uv_stream_t stream;
	} uv;
	zval *listen_cb;
	zval *read_cb;
	zval *write_cb;
	zval *close_cb;
	zval *timer_cb;
	zval *idle_cb;
	zval *connect_cb;
} php_uv_t;

#define PHP_UV_RESOURCE_NAME "uv"
#define PHP_UV_LOOP_RESOURCE_NAME "uv_loop"
#define PHP_UV_CONNECT_RESOURCE_NAME "uv_connect"

#endif /* PHP_UV_H */

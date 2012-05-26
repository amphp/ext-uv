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

/* TODO: fix lator */
typedef struct {
	struct sockaddr_in addr;
	uv_connect_t connect;
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
	int resource_id;
	zval *listen_cb;
	zval *read_cb;
	zval *write_cb;
	zval *close_cb;
	/* TODO: remove lator */
	zend_fcall_info fci_connect;
	zend_fcall_info_cache fcc_connect;
	zend_fcall_info fci_listen;
	zend_fcall_info_cache fcc_listen;
} php_uv_t;

#define PHP_UV_RESOURCE_NAME "uv"
#define PHP_UV_CONNECT_RESOURCE_NAME "uv_connect"

#endif /* PHP_UV_H */

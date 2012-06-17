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

enum php_uv_resource_type{
	IS_UV_TCP = 0,
	IS_UV_UDP = 1,
	IS_UV_PIPE = 2,
	IS_UV_IDLE = 3,
	IS_UV_TIMER = 4,
	IS_UV_ASYNC = 5,
	IS_UV_LOOP = 6,
	IS_UV_HANDLE = 7,
	IS_UV_STREAM = 8,
	IS_UV_ADDRINFO = 9,
	IS_UV_PROCESS = 10,
	IS_UV_MAX = 11
};

typedef struct {
	int in_free;
#ifdef ZTS
	void ***thread_ctx;
#endif
	int resource_id;
	int type;
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
		uv_getaddrinfo_t addrinfo;
		uv_process_t process;
	} uv;
	zval *address;
	zval *listen_cb;
	zval *read_cb;
	zval *write_cb;
	zval *close_cb;
	zval *timer_cb;
	zval *idle_cb;
	zval *connect_cb;
	zval *getaddr_cb;
	zval *udp_recv_cb;
	zval *udp_send_cb;
	zval *pipe_connect_cb;
	zval *proc_close_cb;
} php_uv_t;

typedef struct {
	ares_channel channel;
	struct ares_options options;
	zval *gethostbyname_cb;
	zval *gethostbyaddr_cb;
	int resource_id;
} php_uv_ares_t;

typedef struct {
	int is_ipv4;
	int resource_id;
	union {
		struct sockaddr_in ipv4;
		struct sockaddr_in6 ipv6;
	} addr;
} php_uv_sockaddr_t;

#define PHP_UV_RESOURCE_NAME "uv"
#define PHP_UV_SOCKADDR_RESOURCE_NAME "uv_sockaddr"
#define PHP_UV_LOOP_RESOURCE_NAME "uv_loop"
#define PHP_UV_ARES_RESOURCE_NAME "uv_ares"
#define PHP_UV_RWLOCK_RESOURCE_NAME "uv_rwlock"
#define PHP_UV_MUTEX_RESOURCE_NAME "uv_mutex"

#endif /* PHP_UV_H */

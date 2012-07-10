#ifndef PHP_UV_H

#define PHP_UV_H

#define PHP_UV_EXTNAME "uv"
#define PHP_UV_EXTVER "0.0.1"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef PHP_WIN32
#include <Winsock2.h>
#include <Mswsock.h>
#include <psapi.h>
#include <Iphlpapi.h>
#endif

#include "php.h"
#include "uv.h"
#include "http_parser.h"

#include "zend_interfaces.h"

/* Define the entry point symbol
 * Zend will use when loading this module
 */
extern zend_module_entry uv_module_entry;
#define phpext_uv_ptr &uv_module_entry;

extern zend_class_entry *uv_class_entry;

enum php_uv_lock_type{
	IS_UV_RWLOCK = 1,
	IS_UV_MUTEX = 2,
	IS_UV_SEMAPHORE = 3,
};

enum php_uv_resource_type{
	IS_UV_TCP      = 0,
	IS_UV_UDP      = 1,
	IS_UV_PIPE     = 2,
	IS_UV_IDLE     = 3,
	IS_UV_TIMER    = 4,
	IS_UV_ASYNC    = 5,
	IS_UV_LOOP     = 6,
	IS_UV_HANDLE   = 7,
	IS_UV_STREAM   = 8,
	IS_UV_ADDRINFO = 9,
	IS_UV_PROCESS  = 10,
	IS_UV_PREPARE  = 11,
	IS_UV_CHECK    = 12,
	IS_UV_WORK     = 13,
	IS_UV_FS       = 14,
	IS_UV_FS_EVENT = 15,
	IS_UV_TTY      = 16,
	IS_UV_FS_POLL  = 17,
	IS_UV_POLL     = 18,
	IS_UV_MAX      = 19
};

typedef struct {
    zend_fcall_info fci;
    zend_fcall_info_cache fcc;
} php_uv_cb_t;

typedef struct {
	int in_free;
#ifdef ZTS
	void ***thread_ctx;
#endif
	int resource_id;
	int type;
	uv_os_sock_t sock;
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
		uv_prepare_t prepare;
		uv_check_t check;
		uv_process_t process;
		uv_work_t work;
		uv_fs_t fs;
		uv_fs_event_t fs_event;
		uv_tty_t tty;
		uv_fs_poll_t fs_poll;
		uv_poll_t poll;
	} uv;
	char *buffer;
	zval *address;
	zval *listen_cb;
	zval *read_cb;
	zval *read2_cb;
	zval *write_cb;
	zval *shutdown_cb;
	zval *close_cb;
	zval *timer_cb;
	zval *idle_cb;
	zval *connect_cb;
	zval *getaddr_cb;
	zval *udp_recv_cb;
	zval *udp_send_cb;
	zval *pipe_connect_cb;
	zval *proc_close_cb;
	zval *prepare_cb;
	zval *check_cb;
	zval *async_cb;
	zval *work_cb;
	zval *after_work_cb;
	zval *fs_cb;
	zval *fs_event_cb;
	zval *fs_poll_cb;
	zval *poll_cb;
	php_uv_cb_t *callback[20];
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

typedef struct {
	int locked;
	enum php_uv_lock_type type;
	int resource_id;
	union {
		uv_rwlock_t rwlock;
		uv_mutex_t mutex;
		uv_sem_t semaphore;
	} lock;
} php_uv_lock_t;


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
} php_http_parser_context;

#define PHP_UV_HTTPPARSER_RESOURCE_NAME "uv_httpparser"

#define PHP_UV_RESOURCE_NAME "uv"
#define PHP_UV_SOCKADDR_RESOURCE_NAME "uv_sockaddr"
#define PHP_UV_LOOP_RESOURCE_NAME "uv_loop"
#define PHP_UV_ARES_RESOURCE_NAME "uv_ares"
#define PHP_UV_LOCK_RESOURCE_NAME "uv_lock"
#define PHP_UV_MUTEX_RESOURCE_NAME "uv_mutex"


#if PHP_VERSION_ID>=50399
#define PHP_UV_LIST_INSERT(type, handle) zend_list_insert(type, handle TSRMLS_CC)
#else
#define PHP_UV_LIST_INSERT(type, handle) zend_list_insert(type, handle)
#endif

/* TODO: remove these macro when libuv provides uv_inet_ntop & uv_inet_pton */
#ifdef PHP_WIN32
# include "libuv/src/ares/inet_net_pton.h"
# include <Ws2tcpip.h>
# define uv_inet_pton ares_inet_pton
# define uv_inet_ntop ares_inet_ntop
#else
# include <arpa/inet.h>
# define uv_inet_pton inet_pton
# define uv_inet_ntop inet_ntop
#endif

#endif /* PHP_UV_H */

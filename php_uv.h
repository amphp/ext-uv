#ifndef PHP_UV_H

#define PHP_UV_H

#define PHP_UV_EXTNAME "uv"
#define PHP_UV_VERSION "0.3.0"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef PHP_WIN32
#include <Winsock2.h>
#include <Mswsock.h>
#include <psapi.h>
#include <Iphlpapi.h>
#endif

#ifndef PHP_UV_DTRACE
#define PHP_UV_DTRACE 0
#endif

#if PHP_UV_DTRACE >= 1
#include <dtrace.h>
#include <sys/sdt.h>
#include "phpuv_dtrace.h"
#define PHP_UV_PROBE(PROBE) PHPUV_TRACE_##PROBE();
#else
#define PHP_UV_PROBE(PROBE)
#endif

#include "php.h"
#include "uv.h"

#include "php_network.h"
#include "php_streams.h"

#if defined(HAVE_SOCKETS) && !defined(COMPILE_DL_SOCKETS)
#include "ext/sockets/php_sockets.h"
#elif !defined(PHP_WIN32)
typedef struct {
	int bsd_socket;
	int type;
	int error;
	int blocking;
	zval zstream;
	zend_object std;
} php_socket;
#endif

#include <Zend/zend.h>
#include <Zend/zend_compile.h>
#include <Zend/zend_exceptions.h>
#include <Zend/zend_extensions.h>
#include <Zend/zend_globals.h>
#include <Zend/zend_hash.h>
#include <Zend/zend_ts_hash.h>
#include <Zend/zend_interfaces.h>
#include <Zend/zend_list.h>
#include <Zend/zend_object_handlers.h>
#include <Zend/zend_variables.h>
#include <Zend/zend_vm.h>

#if PHP_VERSION_ID >= 80000
#define TSRMLS_C
#define TSRMLS_CC
#define TSRMLS_D
#define TSRMLS_DC
#define TSRMLS_FETCH_FROM_CTX(ctx)
#define TSRMLS_SET_CTX(ctx)
#endif

/* Define the entry point symbol
 * Zend will use when loading this module
 */
extern zend_module_entry uv_module_entry;
#define phpext_uv_ptr &uv_module_entry

extern zend_class_entry *uv_class_entry;

enum php_uv_lock_type {
	IS_UV_RWLOCK = 1,
	IS_UV_RWLOCK_RD = 2,
	IS_UV_RWLOCK_WR = 3,
	IS_UV_MUTEX = 4,
	IS_UV_SEMAPHORE = 5,
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
	IS_UV_SIGNAL   = 19,
	IS_UV_MAX      = 20
};

enum php_uv_callback_type{
	PHP_UV_LISTEN_CB       = 0,
	PHP_UV_READ_CB         = 1,
	PHP_UV_READ2_CB        = 2,
	PHP_UV_WRITE_CB        = 3,
	PHP_UV_SHUTDOWN_CB     = 4,
	PHP_UV_CLOSE_CB        = 5,
	PHP_UV_TIMER_CB        = 6,
	PHP_UV_IDLE_CB         = 7,
	PHP_UV_CONNECT_CB      = 8,
	PHP_UV_GETADDR_CB      = 9,
	PHP_UV_RECV_CB         = 10,
	PHP_UV_SEND_CB         = 11,
	PHP_UV_PIPE_CONNECT_CB = 12,
	PHP_UV_PROC_CLOSE_CB   = 13,
	PHP_UV_PREPARE_CB      = 14,
	PHP_UV_CHECK_CB        = 15,
	PHP_UV_ASYNC_CB        = 16,
	PHP_UV_WORK_CB         = 17,
	PHP_UV_AFTER_WORK_CB   = 18,
	PHP_UV_FS_CB           = 19,
	PHP_UV_FS_EVENT_CB     = 20,
	PHP_UV_FS_POLL_CB      = 21,
	PHP_UV_POLL_CB         = 22,
	PHP_UV_SIGNAL_CB       = 23,
	PHP_UV_CB_MAX          = 24
};

typedef struct {
    zend_fcall_info fci;
    zend_fcall_info_cache fcc;
} php_uv_cb_t;

typedef struct {
	zend_object std;

#if defined(ZTS) && PHP_VERSION_ID < 80000
	void ***thread_ctx;
#endif
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
		uv_req_t req;
		uv_stream_t stream;
		uv_shutdown_t shutdown;
		uv_udp_send_t udp_send;
		uv_connect_t connect;
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
		uv_signal_t signal;
	} uv;
	char *buffer;
	php_uv_cb_t *callback[PHP_UV_CB_MAX];
	zval gc_data[PHP_UV_CB_MAX * 2];
	zval fs_fd;
	zval fs_fd_alt;
} php_uv_t;

typedef struct {
	zend_object std;

	union {
		struct sockaddr_in ipv4;
		struct sockaddr_in6 ipv6;
	} addr;
} php_uv_sockaddr_t;

typedef struct {
	zend_object std;

	int locked;
	enum php_uv_lock_type type;
	union {
		uv_rwlock_t rwlock;
		uv_mutex_t mutex;
		uv_sem_t semaphore;
	} lock;
} php_uv_lock_t;

typedef struct {
	zend_object std;

	int fd;
	zval stream;
	int flags;
} php_uv_stdio_t;

typedef struct {
	zend_object std;

	uv_loop_t loop;

	size_t gc_buffer_size;
	zval *gc_buffer;
} php_uv_loop_t;

/* File/directory stat mode constants*/
#ifdef PHP_WIN32
#define S_IFDIR _S_IFDIR
#define S_IFREG _S_IFREG
#else
#ifndef S_IFDIR
#define S_IFDIR 0040000
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif
#endif

ZEND_BEGIN_MODULE_GLOBALS(uv)
	php_uv_loop_t *default_loop;
ZEND_END_MODULE_GLOBALS(uv)

#ifdef ZTS
#ifdef COMPILE_DL_UV
ZEND_TSRMLS_CACHE_EXTERN()
#endif

#define UV_G(v) TSRMG(uv_globals_id, zend_uv_globals *, v)
#else
#define UV_G(v) (uv_globals.v)
#endif

#endif /* PHP_UV_H */

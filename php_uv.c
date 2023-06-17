/*
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Shuhei Tanuma <chobieeee@php.net>                           |
   |          Bob Weinand <bobwei9@hotmail.com>                           |
   +----------------------------------------------------------------------+
 */

#pragma GCC diagnostic ignored "-Wmissing-braces"

#include "php_uv.h"
#include "php_main.h"
#include "ext/standard/info.h"
#include "zend_smart_str.h"

#ifndef PHP_UV_DEBUG
#define PHP_UV_DEBUG 0
#endif

#if defined(ZTS) && PHP_VERSION_ID < 80000
#undef TSRMLS_C
#undef TSRMLS_CC
#undef TSRMLS_D
#undef TSRMLS_DC
#define TSRMLS_C tsrm_ls
#define TSRMLS_CC , TSRMLS_C
#define TSRMLS_D void *tsrm_ls
#define TSRMLS_DC , TSRMLS_D

#ifdef COMPILE_DL_UV
ZEND_TSRMLS_CACHE_DEFINE()
#endif
#endif

ZEND_DECLARE_MODULE_GLOBALS(uv);

#ifndef GC_ADDREF
	#define GC_ADDREF(ref) ++GC_REFCOUNT(ref)
#endif

#if PHP_VERSION_ID < 70100
	#define uv_zend_wrong_parameter_class_error(throw, ...) zend_wrong_paramer_class_error(__VA_ARGS__)
#elif PHP_VERSION_ID < 70200 || PHP_VERSION_ID >= 70300
	#define uv_zend_wrong_parameter_class_error(throw, ...) zend_wrong_parameter_class_error(__VA_ARGS__)
#else
	#define uv_zend_wrong_parameter_class_error(...) zend_wrong_parameter_class_error(__VA_ARGS__)
#endif

#if PHP_VERSION_ID < 70200
	#define UV_PARAM_PROLOGUE Z_PARAM_PROLOGUE(0)
#else
	#define UV_PARAM_PROLOGUE Z_PARAM_PROLOGUE(0, 0)
#endif

#if PHP_VERSION_ID < 70400
	#define _error_code error_code
#endif

#if PHP_VERSION_ID >= 80000
#define zend_internal_type_error(strict_types, ...) zend_type_error(__VA_ARGS__)
#endif

#define UV_PARAM_OBJ_EX(dest, type, check_null, ce, ...) \
	{ \
		zval *zv; \
		UV_PARAM_PROLOGUE \
		if (UNEXPECTED(!uv_parse_arg_object(_arg, &zv, check_null, ce, ##__VA_ARGS__, NULL))) { \
			if (!(_flags & ZEND_PARSE_PARAMS_QUIET)) { \
				zend_string *names = php_uv_concat_ce_names(ce, ##__VA_ARGS__, NULL); \
				uv_zend_wrong_parameter_class_error(_flags & ZEND_PARSE_PARAMS_THROW, _i, ZSTR_VAL(names), _arg); \
				zend_string_release(names); \
			} \
			_error_code = ZPP_ERROR_FAILURE; \
			break; \
		} \
		if (GC_FLAGS(Z_OBJ_P(zv)) & IS_OBJ_DESTRUCTOR_CALLED) { \
			if (!(_flags & ZEND_PARSE_PARAMS_QUIET)) { \
				php_error_docref(NULL, E_WARNING, "passed %s handle is already closed", ZSTR_VAL(Z_OBJCE_P(_arg)->name)); \
			} \
			_error_code = ZPP_ERROR_FAILURE; \
			break; \
		} \
		dest = zv == NULL ? NULL : (type *) Z_OBJ_P(zv); \
	}

#define UV_PARAM_OBJ(dest, type, ...) UV_PARAM_OBJ_EX(dest, type, 0, ##__VA_ARGS__, NULL)
#define UV_PARAM_OBJ_NULL(dest, type, ...) UV_PARAM_OBJ_EX(dest, type, 1, ##__VA_ARGS__, NULL)

static ZEND_COLD zend_string *php_uv_concat_ce_names(zend_class_entry *ce, zend_class_entry *next, ...) {
	va_list va;
	smart_str buf = {0};

	va_start(va, next);

	if (!next) {
		return zend_string_copy(ce->name);
	}

	goto start;
	do {
		if (next) {
			smart_str_appends(&buf, ", ");
		} else {
			smart_str_appends(&buf, " or ");
		}
start:
		smart_str_append(&buf, ce->name);
		ce = next;
		next = (zend_class_entry *) va_arg(va, zend_class_entry *);
	} while (next);

	va_end(va);

	smart_str_0(&buf);
	return buf.s;
}

/* gcc complains: sorry, unimplemented: function ‘uv_parse_arg_object’ can never be inlined because it uses variable argument lists */
#ifdef __clang__
static zend_always_inline int uv_parse_arg_object(zval *arg, zval **dest, int check_null, zend_class_entry *ce, ...) {
#else
static int uv_parse_arg_object(zval *arg, zval **dest, int check_null, zend_class_entry *ce, ...) {
#endif
	if (EXPECTED(Z_TYPE_P(arg) == IS_OBJECT)) {
		va_list va;
		zend_class_entry *argce = Z_OBJCE_P(arg);
		va_start(va, ce);
		do {
			if (instanceof_function(argce, ce)) {
				*dest = arg;
				return 1;
			}
			ce = (zend_class_entry *) va_arg(va, zend_class_entry *);
		} while (ce);
	} else if (check_null && EXPECTED(Z_TYPE_P(arg) == IS_NULL)) {
		*dest = NULL;
		return 1;
	}
	return 0;
}

#define PHP_UV_DEINIT_UV(uv) \
	clean_uv_handle(uv); \
	OBJ_RELEASE(&uv->std);

#define PHP_UV_INIT_GENERIC(dest, type, ce) \
	do { \
		zval zv; \
		object_init_ex(&zv, ce); \
		dest = (type *) Z_OBJ(zv); \
	} while (0)

#define PHP_UV_INIT_UV(uv, ce) PHP_UV_INIT_GENERIC(uv, php_uv_t, ce)

#define PHP_UV_INIT_UV_EX(_uv, ce, cb, ...) \
	do { \
		int r; \
		PHP_UV_INIT_UV(_uv, ce); \
		r = cb(&loop->loop, (void *) &_uv->uv.handle, ##__VA_ARGS__); \
		if (r) { \
			PHP_UV_DEINIT_UV(_uv); \
			php_error_docref(NULL, E_WARNING, #cb " failed"); \
			RETURN_FALSE; \
		} \
	} while (0)

#define PHP_UV_INIT_CONNECT(req, uv) \
	req = (uv_connect_t *) emalloc(sizeof(uv_connect_t)); \
	req->data = uv;

#define PHP_UV_INIT_WRITE_REQ(w, uv, str, strlen, cb) \
	w = (write_req_t *) emalloc(sizeof(write_req_t)); \
	w->req.data = uv; \
	w->buf = uv_buf_init(estrndup(str, strlen), strlen); \
	w->cb = cb; \

#define PHP_UV_INIT_SEND_REQ(w, uv, str, strlen) \
	w = (send_req_t *) emalloc(sizeof(send_req_t)); \
	w->req.data = uv; \
	w->buf = uv_buf_init(estrndup(str, strlen), strlen); \

#define PHP_UV_FETCH_UV_DEFAULT_LOOP(loop) \
	if (loop == NULL) { \
		loop = php_uv_default_loop(); \
	}  \

#define PHP_UV_INIT_LOCK(lock, lock_type) \
	PHP_UV_INIT_GENERIC(lock, php_uv_lock_t, uv_lock_ce); \
	lock->type = lock_type;

#define PHP_UV_CHECK_VALID_FD(fd, zstream) \
	if (fd < 0) { \
		php_error_docref(NULL, E_WARNING, "invalid variable passed. can't convert to fd."); \
		PHP_UV_DEINIT_UV(uv); \
		RETURN_FALSE; \
	} \
	if (Z_ISUNDEF(uv->fs_fd)) { \
		ZVAL_COPY(&uv->fs_fd, zstream); \
	}

#define PHP_UV_ZVAL_TO_VALID_POLL_FD(fd, zstream) \
{ \
	fd = php_uv_zval_to_valid_poll_fd(zstream); \
	PHP_UV_CHECK_VALID_FD(fd, zstream) \
}

#define PHP_UV_ZVAL_TO_FD(fd, zstream) \
{ \
	fd = php_uv_zval_to_fd(zstream); \
	PHP_UV_CHECK_VALID_FD(fd, zstream) \
}

#define PHP_UV_FS_ASYNC(loop, func,  ...) \
	error = uv_fs_##func(&loop->loop, (uv_fs_t*)&uv->uv.fs, __VA_ARGS__, php_uv_fs_cb); \
	if (error) { \
		PHP_UV_DEINIT_UV(uv); \
		php_error_docref(NULL, E_WARNING, "uv_" #func " failed"); \
		return; \
	}

#define PHP_UV_INIT_ZVALS(uv) \
	{ \
		int ix = 0;\
		for (ix = 0; ix < PHP_UV_CB_MAX; ix++) {\
			uv->callback[ix] = NULL;\
		} \
		ZVAL_UNDEF(&uv->fs_fd); \
		ZVAL_UNDEF(&uv->fs_fd_alt); \
	}

#if PHP_VERSION_ID < 70300
 #define PHP_UV_SKIP_DTOR(uv) do { GC_FLAGS(&uv->std) |= IS_OBJ_DESTRUCTOR_CALLED; } while (0)
#else
 #define PHP_UV_SKIP_DTOR(uv) do { GC_ADD_FLAGS(&uv->std, IS_OBJ_DESTRUCTOR_CALLED); } while (0)
#endif
#define PHP_UV_IS_DTORED(uv) (GC_FLAGS(&uv->std) & IS_OBJ_DESTRUCTOR_CALLED)

#define PHP_UV_SOCKADDR_IPV4_INIT(sockaddr) PHP_UV_INIT_GENERIC(sockaddr, php_uv_sockaddr_t, uv_sockaddr_ipv4_ce);
#define PHP_UV_SOCKADDR_IPV6_INIT(sockaddr) PHP_UV_INIT_GENERIC(sockaddr, php_uv_sockaddr_t, uv_sockaddr_ipv6_ce);

#define PHP_UV_SOCKADDR_IS_IPV4(sockaddr) (sockaddr->std.ce == uv_sockaddr_ipv4_ce)
#define PHP_UV_SOCKADDR_IS_IPV6(sockaddr) (sockaddr->std.ce == uv_sockaddr_ipv6_ce)

#define PHP_UV_SOCKADDR_IPV4(sockaddr) sockaddr->addr.ipv4
#define PHP_UV_SOCKADDR_IPV4_P(sockaddr) &sockaddr->addr.ipv4

#define PHP_UV_SOCKADDR_IPV6(sockaddr) sockaddr->addr.ipv6
#define PHP_UV_SOCKADDR_IPV6_P(sockaddr) &sockaddr->addr.ipv6

#define PHP_UV_LOCK_RWLOCK_P(_lock) &_lock->lock.rwlock
#define PHP_UV_LOCK_MUTEX_P(_lock) &_lock->lock.mutex
#define PHP_UV_LOCK_SEM_P(_lock) &_lock->lock.semaphore

#define PHP_UV_FD_TO_ZVAL(zv, fd) { php_stream *_stream = php_stream_fopen_from_fd(fd, "w+", NULL); zval *_z = (zv); php_stream_to_zval(_stream, _z); }

#if PHP_UV_DEBUG>=1
#define PHP_UV_DEBUG_PRINT(format, ...) fprintf(stderr, format, ## __VA_ARGS__)
#else
#define PHP_UV_DEBUG_PRINT(format, ...)
#endif

#if PHP_UV_DEBUG>=1
#define PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(handler, uv) \
	{ \
		PHP_UV_DEBUG_PRINT("# %s add(%p - %s): %u->%u\n", #handler, uv, ZSTR_VAL(uv->std.ce->name), GC_REFCOUNT(&(uv)->std) - 1, GC_REFCOUNT(&(uv)->std)); \
	}
#define PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(handler, uv) \
	{ \
		PHP_UV_DEBUG_PRINT("# %s del(%p - %s): %u->%u\n", #handler, uv, ZSTR_VAL(uv->std.ce->name), GC_REFCOUNT(&(uv)->std), GC_REFCOUNT(&(uv)->std) - 1); \
	}
#else
#define PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(hander, uv)
#define PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(hander, uv)
#endif

#if defined(ZTS) && PHP_VERSION_ID < 80000
#define UV_FETCH_ALL(ls, id, type) ((type) (*((void ***) ls))[TSRM_UNSHUFFLE_RSRC_ID(id)])
#define UV_FETCH_CTX(ls, id, type, element) (((type) (*((void ***) ls))[TSRM_UNSHUFFLE_RSRC_ID(id)])->element)
#define UV_CG(ls, v)  UV_FETCH_CTX(ls, compiler_globals_id, zend_compiler_globals*, v)
#define UV_CG_ALL(ls) UV_FETCH_ALL(ls, compiler_globals_id, zend_compiler_globals*)
#define UV_EG(ls, v)  UV_FETCH_CTX(ls, executor_globals_id, zend_executor_globals*, v)
#define UV_SG(ls, v)  UV_FETCH_CTX(ls, sapi_globals_id, sapi_globals_struct*, v)
#define UV_EG_ALL(ls) UV_FETCH_ALL(ls, executor_globals_id, zend_executor_globals*)
#endif

#if !defined(PHP_WIN32) && !(defined(HAVE_SOCKETS) && !defined(COMPILE_DL_SOCKETS))
# if PHP_VERSION_ID >= 80000
__attribute__((weak)) zend_class_entry *socket_ce = NULL;
# else
int (*php_sockets_le_socket_ptr)(void) = NULL;
int php_sockets_le_socket(void) __attribute__((weak));
# endif
#endif

/* objects */
extern void php_uv_init(zend_class_entry *uv_ce);

static zend_object_handlers uv_default_handlers;

static zend_class_entry *uv_ce;
static zend_object_handlers uv_handlers;

static zend_class_entry *uv_stream_ce;

static zend_class_entry *uv_tcp_ce;
static zend_class_entry *uv_udp_ce;
static zend_class_entry *uv_pipe_ce;
static zend_class_entry *uv_idle_ce;
static zend_class_entry *uv_timer_ce;
static zend_class_entry *uv_async_ce;
static zend_class_entry *uv_addrinfo_ce;
static zend_class_entry *uv_process_ce;
static zend_class_entry *uv_prepare_ce;
static zend_class_entry *uv_check_ce;
static zend_class_entry *uv_work_ce;
static zend_class_entry *uv_fs_ce;
static zend_class_entry *uv_fs_event_ce;
static zend_class_entry *uv_tty_ce;
static zend_class_entry *uv_fs_poll_ce;
static zend_class_entry *uv_poll_ce;
static zend_class_entry *uv_signal_ce;

static zend_class_entry *uv_loop_ce;
static zend_object_handlers uv_loop_handlers;

static zend_class_entry *uv_sockaddr_ce;

static zend_class_entry *uv_sockaddr_ipv4_ce;
static zend_class_entry *uv_sockaddr_ipv6_ce;

static zend_class_entry *uv_lock_ce;
static zend_object_handlers uv_lock_handlers;

static zend_class_entry *uv_stdio_ce;
static zend_object_handlers uv_stdio_handlers;


typedef struct {
	uv_write_t req;
	uv_buf_t buf;
	php_uv_cb_t *cb;
} write_req_t;

typedef struct {
	uv_udp_send_t req;
	uv_buf_t buf;
} send_req_t;

enum php_uv_socket_type {
	PHP_UV_TCP_IPV4 = 1,
	PHP_UV_TCP_IPV6 = 2,
	PHP_UV_TCP      = 3,
	PHP_UV_UDP_IPV4 = 16,
	PHP_UV_UDP_IPV6 = 32,
	PHP_UV_UDP      = 48,
};

/* declarations */

static void php_uv_fs_cb(uv_fs_t* req);
/**
 * execute callback
 *
 * @param zval* retval_ptr non-initialized pointer. this will be allocate from zend_call_function
 * @param php_uv_cb_t* callback callable object
 * @param zval* params parameters.
 * @param int param_count
 * @return int (maybe..)
 */
static int php_uv_do_callback(zval *retval_ptr, php_uv_cb_t *callback, zval *params, int param_count TSRMLS_DC);

void static destruct_uv(zend_object *obj);
void static clean_uv_handle(php_uv_t *uv);

static void php_uv_tcp_connect_cb(uv_connect_t *conn_req, int status);

static void php_uv_write_cb(uv_write_t* req, int status);

static void php_uv_listen_cb(uv_stream_t* server, int status);

static void php_uv_shutdown_cb(uv_shutdown_t* req, int status);

static void php_uv_read_cb(uv_stream_t* handle, ssize_t nread,const uv_buf_t* buf);

/* unused: static void php_uv_read2_cb(uv_pipe_t* handle, ssize_t nread, uv_buf_t buf, uv_handle_type pending); */

static void php_uv_read_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);

static void php_uv_close(php_uv_t *uv);

static void php_uv_timer_cb(uv_timer_t *handle);

static void php_uv_idle_cb(uv_timer_t *handle);

static void php_uv_signal_cb(uv_signal_t *handle, int sig_num);


static php_uv_loop_t *php_uv_default_loop()
{
	if (UV_G(default_loop) == NULL) {
		zval zv;
		object_init_ex(&zv, uv_loop_ce);
		UV_G(default_loop) = (php_uv_loop_t *) Z_OBJ(zv);
	}

	return UV_G(default_loop);
}

static php_socket_t php_uv_zval_to_valid_poll_fd(zval *ptr)
{
	php_socket_t fd = -1;
	php_stream *stream;

	/* Validate Checks */

#if !defined(PHP_WIN32) || (defined(HAVE_SOCKETS) && !defined(COMPILE_DL_SOCKETS))
	php_socket *socket;
#endif
	/* TODO: is this correct on windows platform? */
	if (Z_TYPE_P(ptr) == IS_RESOURCE) {
		if ((stream = (php_stream *) zend_fetch_resource_ex(ptr, NULL, php_file_le_stream()))) {
			/* make sure only valid resource streams are passed - plainfiles and most php streams are invalid */
			if (stream->wrapper && !strcmp((char *)stream->wrapper->wops->label, "PHP") && (!stream->orig_path || (strncmp(stream->orig_path, "php://std", sizeof("php://std") - 1) && strncmp(stream->orig_path, "php://fd", sizeof("php://fd") - 1)))) {
				php_error_docref(NULL, E_WARNING, "invalid resource passed, this resource is not supported");
				return -1;
			}

			/* Some streams (specifically STDIO and encrypted streams) can be cast to FDs */
			if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void*)&fd, 1) == SUCCESS && fd >= 0) {
				if (stream->wrapper && !strcmp((char *)stream->wrapper->wops->label, "plainfile")) {
#ifndef PHP_WIN32
					struct stat stat;
					fstat(fd, &stat);
					if (!S_ISFIFO(stat.st_mode))
#endif
					{
						php_error_docref(NULL, E_WARNING, "invalid resource passed, this plain files are not supported");
						return -1;
					}
				}
				return fd;
			}

			fd = -1;
#if PHP_VERSION_ID < 80000 && (!defined(PHP_WIN32) || (defined(HAVE_SOCKETS) && !defined(COMPILE_DL_SOCKETS)))
		} else if (php_sockets_le_socket_ptr && (socket = (php_socket *) zend_fetch_resource_ex(ptr, NULL, php_sockets_le_socket_ptr()))) {
			fd = socket->bsd_socket;
#endif
		} else {
			php_error_docref(NULL, E_WARNING, "unhandled resource type detected.");
			fd = -1;
		}
#if PHP_VERSION_ID >= 80000 && (!defined(PHP_WIN32) || (defined(HAVE_SOCKETS) && !defined(COMPILE_DL_SOCKETS)))
	} else if (socket_ce && Z_TYPE_P(ptr) == IS_OBJECT && Z_OBJCE_P(ptr) == socket_ce && (socket = (php_socket *) ((char *)(Z_OBJ_P(ptr)) - XtOffsetOf(php_socket, std)))) {
		fd = socket->bsd_socket;
#endif
	}

	return fd;
}

static php_socket_t php_uv_zval_to_fd(zval *ptr)
{
	php_socket_t fd = -1;
	php_stream *stream;
#if !defined(PHP_WIN32) || (defined(HAVE_SOCKETS) && !defined(COMPILE_DL_SOCKETS))
	php_socket *socket;
#endif
	/* TODO: is this correct on windows platform? */
	if (Z_TYPE_P(ptr) == IS_RESOURCE) {
		if ((stream = (php_stream *) zend_fetch_resource_ex(ptr, NULL, php_file_le_stream()))) {
			if (php_stream_cast(stream, PHP_STREAM_AS_FD | PHP_STREAM_CAST_INTERNAL, (void *) &fd, 1) != SUCCESS || fd < 0) {
				fd = -1;
			}
#if PHP_VERSION_ID < 80000 && (!defined(PHP_WIN32) || (defined(HAVE_SOCKETS) && !defined(COMPILE_DL_SOCKETS)))
		} else if (php_sockets_le_socket_ptr && (socket = (php_socket *) zend_fetch_resource_ex(ptr, NULL, php_sockets_le_socket_ptr()))) {
			fd = socket->bsd_socket;
#endif
		} else {
			php_error_docref(NULL, E_WARNING, "unhandled resource type detected.");
			fd = -1;
		}
	} else if (Z_TYPE_P(ptr) == IS_LONG) {
		fd = Z_LVAL_P(ptr);
		if (fd < 0) {
			fd = -1;
		}

		{
			/* make sure that a valid resource handle was passed - issue #36 */
			int err = uv_guess_handle((uv_file) fd);
			if (err == UV_UNKNOWN_HANDLE) {
				php_error_docref(NULL, E_WARNING, "invalid resource type detected");
				fd = -1;
			}
		}
#if PHP_VERSION_ID >= 80000 && (!defined(PHP_WIN32) || (defined(HAVE_SOCKETS) && !defined(COMPILE_DL_SOCKETS)))
	} else if (socket_ce && Z_TYPE_P(ptr) == IS_OBJECT && Z_OBJCE_P(ptr) == socket_ce && (socket = (php_socket *) ((char *)(Z_OBJ_P(ptr)) - XtOffsetOf(php_socket, std)))) {
		fd = socket->bsd_socket;
#endif
	}

	return fd;
}

static const char* php_uv_strerror(long error_code)
{
	/* Note: uv_strerror doesn't use assert. we don't need check value here */
	return uv_strerror(error_code);
}

static php_uv_cb_t* php_uv_cb_init_dynamic(php_uv_t *uv, zend_fcall_info *fci, zend_fcall_info_cache *fcc) {
	php_uv_cb_t *cb = emalloc(sizeof(php_uv_cb_t));

	memcpy(&cb->fci, fci, sizeof(zend_fcall_info));
	memcpy(&cb->fcc, fcc, sizeof(zend_fcall_info_cache));

	if (ZEND_FCI_INITIALIZED(*fci)) {
		Z_TRY_ADDREF(cb->fci.function_name);
		if (fci->object) {
			GC_ADDREF(cb->fci.object);
		}
	}

	return cb;
}

static void php_uv_cb_init(php_uv_cb_t **result, php_uv_t *uv, zend_fcall_info *fci, zend_fcall_info_cache *fcc, enum php_uv_callback_type type)
{
	php_uv_cb_t *cb;

	if (uv->callback[type] == NULL) {
		cb = emalloc(sizeof(php_uv_cb_t));
	} else {
		cb = uv->callback[type];

		if (Z_TYPE(cb->fci.function_name) != IS_UNDEF) {
			zval_dtor(&cb->fci.function_name);
		}
		if (fci->object) {
			OBJ_RELEASE(fci->object);
		}
	}

	memcpy(&cb->fci, fci, sizeof(zend_fcall_info));
	memcpy(&cb->fcc, fcc, sizeof(zend_fcall_info_cache));

	if (ZEND_FCI_INITIALIZED(*fci)) {
		Z_TRY_ADDREF(cb->fci.function_name);
		if (fci->object) {
			GC_ADDREF(cb->fci.object);
		}
	}

	uv->callback[type] = cb;
}

static void php_uv_lock_init(enum php_uv_lock_type lock_type, INTERNAL_FUNCTION_PARAMETERS)
{
	php_uv_lock_t *lock = NULL;
	int error = 0;

	switch (lock_type) {
		case IS_UV_RWLOCK:
		case IS_UV_RWLOCK_WR:
		case IS_UV_RWLOCK_RD:
		{
			PHP_UV_INIT_LOCK(lock, IS_UV_RWLOCK);
			error = uv_rwlock_init(PHP_UV_LOCK_RWLOCK_P(lock));
		}
		break;
		case IS_UV_MUTEX:
		{
			PHP_UV_INIT_LOCK(lock, IS_UV_MUTEX);
			error = uv_mutex_init(PHP_UV_LOCK_MUTEX_P(lock));
		}
		break;
		case IS_UV_SEMAPHORE:
		{
			zend_long val = 0;

			if (zend_parse_parameters(ZEND_NUM_ARGS(),
				"l", &val) == FAILURE) {
				return;
			}

			PHP_UV_INIT_LOCK(lock, IS_UV_SEMAPHORE);
			error = uv_sem_init(PHP_UV_LOCK_SEM_P(lock), (int) val);
		}
		break;
		default:
			php_error_docref(NULL, E_ERROR, "unexpected type");
		break;
	}

	if (error == 0) {
		RETURN_OBJ(&lock->std);
	} else {
		OBJ_RELEASE(&lock->std);
		RETURN_FALSE;
	}
}

static void php_uv_lock_lock(enum php_uv_lock_type lock_type, INTERNAL_FUNCTION_PARAMETERS)
{
	php_uv_lock_t *lock;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(lock, php_uv_lock_t, uv_lock_ce)
	ZEND_PARSE_PARAMETERS_END();

	switch (lock_type) {
		case IS_UV_RWLOCK:
		case IS_UV_RWLOCK_RD:
		{
			if (lock->locked == 0x01) {
				zend_error(E_WARNING, "Cannot acquire a read lock while holding a write lock");
				RETURN_FALSE;
			}

			uv_rwlock_rdlock(PHP_UV_LOCK_RWLOCK_P(lock));
			if (!lock->locked++) {
				lock->locked = 0x02;
			}
		}
		break;
		case IS_UV_RWLOCK_WR:
		{
			if (lock->locked) {
				zend_error(E_WARNING, "Cannot acquire a write lock when already holding a lock");
				RETURN_FALSE;
			}

			uv_rwlock_wrlock(PHP_UV_LOCK_RWLOCK_P(lock));
			lock->locked = 0x01;
		}
		break;
		case IS_UV_MUTEX:
		{
			uv_mutex_lock(PHP_UV_LOCK_MUTEX_P(lock));
			lock->locked = 0x01;
		}
		break;
		case IS_UV_SEMAPHORE:
		{
			uv_sem_post(PHP_UV_LOCK_SEM_P(lock));
		}
		break;
		default:
			php_error_docref(NULL, E_ERROR, "unexpected type");
		break;
	}
}

static void php_uv_lock_unlock(enum php_uv_lock_type  lock_type, INTERNAL_FUNCTION_PARAMETERS)
{
	php_uv_lock_t *lock;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(lock, php_uv_lock_t, uv_lock_ce)
	ZEND_PARSE_PARAMETERS_END();

	switch (lock_type) {
		case IS_UV_RWLOCK:
		case IS_UV_RWLOCK_RD:
		{
			if (lock->locked > 0x01) {
				uv_rwlock_rdunlock(PHP_UV_LOCK_RWLOCK_P(lock));
				if (--lock->locked == 0x01) {
					lock->locked = 0x00;
				}
			}
		}
		break;
		case IS_UV_RWLOCK_WR:
		{
			if (lock->locked == 0x01) {
				uv_rwlock_wrunlock(PHP_UV_LOCK_RWLOCK_P(lock));
				lock->locked = 0x00;
			}
		}
		break;
		case IS_UV_MUTEX:
		{
			if (lock->locked == 0x01) {
				uv_mutex_unlock(PHP_UV_LOCK_MUTEX_P(lock));
				lock->locked = 0x00;
			}
		}
		break;
		case IS_UV_SEMAPHORE:
		{
			uv_sem_wait(PHP_UV_LOCK_SEM_P(lock));
		}
		break;
		default:
			php_error_docref(NULL, E_ERROR, "unexpected type");
		break;
	}
}

static void php_uv_lock_trylock(enum php_uv_lock_type lock_type, INTERNAL_FUNCTION_PARAMETERS)
{
	php_uv_lock_t *lock;
	int error = 0;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(lock, php_uv_lock_t, uv_lock_ce)
	ZEND_PARSE_PARAMETERS_END();

	switch(lock_type) {
		case IS_UV_RWLOCK:
		case IS_UV_RWLOCK_RD:
		{
			if (lock->locked == 0x01) {
				zend_error(E_WARNING, "Cannot acquire a read lock while holding a write lock");
				RETURN_FALSE;
			}

			error = uv_rwlock_tryrdlock(PHP_UV_LOCK_RWLOCK_P(lock));
			if (error == 0) {
				if (!lock->locked++) {
					lock->locked = 0x02;
				}
				RETURN_TRUE;
			} else {
				RETURN_FALSE;
			}
		}
		break;
		case IS_UV_RWLOCK_WR:
		{
			if (lock->locked) {
				zend_error(E_WARNING, "Cannot acquire a write lock when already holding a lock");
				RETURN_FALSE;
			}

			error = uv_rwlock_trywrlock(PHP_UV_LOCK_RWLOCK_P(lock));
			if (error == 0) {
				lock->locked = 0x01;
				RETURN_TRUE;
			} else {
				RETURN_FALSE;
			}
		}
		break;
		case IS_UV_MUTEX:
		{
			error = uv_mutex_trylock(PHP_UV_LOCK_MUTEX_P(lock));

			if (error == 0) {
				lock->locked = 0x01;
				RETURN_TRUE;
			} else {
				RETURN_FALSE;
			}
		}
		break;
		case IS_UV_SEMAPHORE:
		{
			error = uv_sem_trywait(PHP_UV_LOCK_SEM_P(lock));
			RETURN_LONG(error);
		}
		default:
			php_error_docref(NULL, E_ERROR, "unexpected type");
		break;
	}
}


static void php_uv_fs_common(uv_fs_type fs_type, INTERNAL_FUNCTION_PARAMETERS)
{
	int error = 0;
	php_uv_loop_t *loop;
	php_uv_t *uv;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

#define PHP_UV_FS_PARSE_PARAMETERS_EX(num, params, required_cb) \
	ZEND_PARSE_PARAMETERS_START(1 + num + required_cb, 2 + num) \
		UV_PARAM_OBJ(loop, php_uv_loop_t, uv_loop_ce) \
		params \
		if (!required_cb) { \
			Z_PARAM_OPTIONAL \
		} \
		Z_PARAM_FUNC_EX(fci, fcc, 1, 0) \
	ZEND_PARSE_PARAMETERS_END()

#define PHP_UV_FS_PARSE_PARAMETERS(num, params) PHP_UV_FS_PARSE_PARAMETERS_EX(num, params, 0)

#define PHP_UV_FS_SETUP() \
	PHP_UV_INIT_UV(uv, uv_fs_ce); \
	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop); \
	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_FS_CB);

#define PHP_UV_FS_SETUP_AND_EXECUTE(command, ...) \
	PHP_UV_FS_SETUP(); \
	PHP_UV_FS_ASYNC(loop, command, __VA_ARGS__);

	switch (fs_type) {
		case UV_FS_SYMLINK:
		{
			zend_string *from, *to;
			zend_long flags;

			PHP_UV_FS_PARSE_PARAMETERS(3, Z_PARAM_STR(from) Z_PARAM_STR(to) Z_PARAM_LONG(flags));
			PHP_UV_FS_SETUP_AND_EXECUTE(symlink, from->val, to->val, flags);
			break;
		}
		case UV_FS_LINK:
		{
			zend_string *from, *to;

			PHP_UV_FS_PARSE_PARAMETERS(2, Z_PARAM_STR(from) Z_PARAM_STR(to));
			PHP_UV_FS_SETUP_AND_EXECUTE(link, from->val, to->val);
			break;
		}
		case UV_FS_CHMOD:
		{
			zend_long mode;
			zend_string *path;

			PHP_UV_FS_PARSE_PARAMETERS(2, Z_PARAM_STR(path) Z_PARAM_LONG(mode));
			PHP_UV_FS_SETUP_AND_EXECUTE(chmod, path->val, mode);
			break;
		}
		case UV_FS_FCHMOD:
		{
			zval *zstream;
			zend_long mode;
			unsigned long fd;

			PHP_UV_FS_PARSE_PARAMETERS(2, Z_PARAM_RESOURCE(zstream) Z_PARAM_LONG(mode));
			PHP_UV_FS_SETUP();
			PHP_UV_ZVAL_TO_FD(fd, zstream);
			uv->fs_fd = *zstream;
			Z_ADDREF(uv->fs_fd);
			PHP_UV_FS_ASYNC(loop, fchmod, fd, mode);
			break;
		}
		case UV_FS_RENAME:
		{
			zend_string *from, *to;

			PHP_UV_FS_PARSE_PARAMETERS(2, Z_PARAM_STR(from) Z_PARAM_STR(to));
			PHP_UV_FS_SETUP_AND_EXECUTE(rename, from->val, to->val);
			break;
		}
		case UV_FS_UNLINK:
		{
			zend_string *path;

			PHP_UV_FS_PARSE_PARAMETERS(1, Z_PARAM_STR(path));
			PHP_UV_FS_SETUP_AND_EXECUTE(unlink, path->val);
			break;
		}
		case UV_FS_RMDIR:
		{
			zend_string *path;

			PHP_UV_FS_PARSE_PARAMETERS(1, Z_PARAM_STR(path));
			PHP_UV_FS_SETUP_AND_EXECUTE(rmdir, path->val);
			break;
		}
		case UV_FS_MKDIR:
		{
			zend_string *path;
			zend_long mode;

			PHP_UV_FS_PARSE_PARAMETERS(2, Z_PARAM_STR(path) Z_PARAM_LONG(mode));
			PHP_UV_FS_SETUP_AND_EXECUTE(mkdir, path->val, mode);
			break;
		}
		case UV_FS_FTRUNCATE:
		{
			zval *zstream = NULL;
			zend_long offset = 0;
			unsigned long fd;

			PHP_UV_FS_PARSE_PARAMETERS(2, Z_PARAM_RESOURCE(zstream) Z_PARAM_LONG(offset));
			PHP_UV_FS_SETUP()
			PHP_UV_ZVAL_TO_FD(fd, zstream);
			uv->fs_fd = *zstream;
			Z_ADDREF(uv->fs_fd);
			PHP_UV_FS_ASYNC(loop, ftruncate, fd, offset);
			break;
		}
		case UV_FS_FDATASYNC:
		{
			zval *zstream = NULL;
			unsigned long fd;

			PHP_UV_FS_PARSE_PARAMETERS(1, Z_PARAM_RESOURCE(zstream));
			PHP_UV_FS_SETUP()
			PHP_UV_ZVAL_TO_FD(fd, zstream);
			uv->fs_fd = *zstream;
			Z_ADDREF(uv->fs_fd);
			PHP_UV_FS_ASYNC(loop, fdatasync, fd);
			break;
		}
		case UV_FS_FSYNC:
		{
			zval *zstream = NULL;
			unsigned long fd;

			PHP_UV_FS_PARSE_PARAMETERS(1, Z_PARAM_RESOURCE(zstream));
			PHP_UV_FS_SETUP()
			PHP_UV_ZVAL_TO_FD(fd, zstream);
			uv->fs_fd = *zstream;
			Z_ADDREF(uv->fs_fd);
			PHP_UV_FS_ASYNC(loop, fsync, fd);
			break;
		}
		case UV_FS_CLOSE:
		{
			zval *zstream = NULL;
			unsigned long fd;

			PHP_UV_FS_PARSE_PARAMETERS(1, Z_PARAM_RESOURCE(zstream));
			PHP_UV_FS_SETUP()
			PHP_UV_ZVAL_TO_FD(fd, zstream);
			uv->fs_fd = *zstream;
			Z_ADDREF(uv->fs_fd);
			PHP_UV_FS_ASYNC(loop, close, fd);
			break;
		}
		case UV_FS_CHOWN:
		{
			zend_long uid, gid;
			zend_string *path;

			PHP_UV_FS_PARSE_PARAMETERS(3, Z_PARAM_STR(path) Z_PARAM_LONG(uid) Z_PARAM_LONG(gid));
			PHP_UV_FS_SETUP_AND_EXECUTE(chown, path->val, uid, gid);
			break;
		}
		case UV_FS_FCHOWN:
		{
			zval *zstream = NULL;
			zend_long uid, gid;
			unsigned long fd;

			PHP_UV_FS_PARSE_PARAMETERS(3, Z_PARAM_RESOURCE(zstream) Z_PARAM_LONG(uid) Z_PARAM_LONG(gid));
			PHP_UV_FS_SETUP()
			PHP_UV_ZVAL_TO_FD(fd, zstream);
			uv->fs_fd = *zstream;
			Z_ADDREF(uv->fs_fd);
			PHP_UV_FS_ASYNC(loop, fchown, fd, uid, gid);
			break;
		}
		case UV_FS_OPEN:
		{
			zend_string *path;
			zend_long flag, mode;

			PHP_UV_FS_PARSE_PARAMETERS_EX(3, Z_PARAM_STR(path) Z_PARAM_LONG(flag) Z_PARAM_LONG(mode), 1);
			PHP_UV_FS_SETUP_AND_EXECUTE(open, path->val, flag, mode);
			break;
		}
		case UV_FS_SCANDIR:
		{
			zend_string *path;
			zend_long flags = 0;

			ZEND_PARSE_PARAMETERS_START(3, 4)
				UV_PARAM_OBJ(loop, php_uv_loop_t, uv_loop_ce)
				Z_PARAM_STR(path)
				Z_PARAM_FUNC_EX(fci, fcc, 1, 0)
				Z_PARAM_OPTIONAL
				Z_PARAM_LONG(flags)
			ZEND_PARSE_PARAMETERS_END();
			PHP_UV_FS_SETUP_AND_EXECUTE(scandir, path->val, flags);
			break;
		}
		case UV_FS_LSTAT:
		{
			zend_string *path;

			PHP_UV_FS_PARSE_PARAMETERS_EX(1, Z_PARAM_STR(path), 1);
			PHP_UV_FS_SETUP_AND_EXECUTE(lstat, path->val);
			break;
		}
		case UV_FS_FSTAT:
		{
			zval *zstream = NULL;
			unsigned long fd;

			PHP_UV_FS_PARSE_PARAMETERS_EX(1, Z_PARAM_RESOURCE(zstream), 1);
			PHP_UV_FS_SETUP()
			PHP_UV_ZVAL_TO_FD(fd, zstream);
			uv->fs_fd = *zstream;
			Z_ADDREF(uv->fs_fd);
			PHP_UV_FS_ASYNC(loop, fstat, fd);
			break;
		}
		case UV_FS_STAT:
		{
			zend_string *path;

			PHP_UV_FS_PARSE_PARAMETERS_EX(1, Z_PARAM_STR(path), 1);
			PHP_UV_FS_SETUP_AND_EXECUTE(stat, path->val);
			break;
		}
		case UV_FS_UTIME:
		{
			zend_long utime, atime;
			zend_string *path;

			PHP_UV_FS_PARSE_PARAMETERS(3, Z_PARAM_STR(path) Z_PARAM_LONG(utime) Z_PARAM_LONG(atime));
			PHP_UV_FS_SETUP_AND_EXECUTE(utime, path->val, utime, atime);
			break;
		}
		case UV_FS_FUTIME:
		{
			zval *zstream = NULL;
			zend_long utime, atime;
			unsigned long fd;

			PHP_UV_FS_PARSE_PARAMETERS(3, Z_PARAM_RESOURCE(zstream) Z_PARAM_LONG(utime) Z_PARAM_LONG(atime));
			PHP_UV_FS_SETUP()
			PHP_UV_ZVAL_TO_FD(fd, zstream);
			uv->fs_fd = *zstream;
			Z_ADDREF(uv->fs_fd);
			PHP_UV_FS_ASYNC(loop, futime, fd, utime, atime);
			break;
		}
		case UV_FS_READLINK:
		{
			zend_string *path;

			PHP_UV_FS_PARSE_PARAMETERS_EX(1, Z_PARAM_STR(path), 1);
			PHP_UV_FS_SETUP_AND_EXECUTE(readlink, path->val);
			break;
		}
		case UV_FS_READ:
		{
			zval *zstream = NULL;
			unsigned long fd;
			zend_long length;
			zend_long offset;
			uv_buf_t buf;

			PHP_UV_FS_PARSE_PARAMETERS_EX(3, Z_PARAM_RESOURCE(zstream) Z_PARAM_LONG(offset) Z_PARAM_LONG(length), 1);
			if (length <= 0) {
				length = 0;
			}
			if (offset < 0) {
				offset = 0;
			}
			PHP_UV_FS_SETUP()
			PHP_UV_ZVAL_TO_FD(fd, zstream);
			uv->fs_fd = *zstream;
			Z_ADDREF(uv->fs_fd);

			uv->buffer = (char*) emalloc(length);
			buf = uv_buf_init(uv->buffer, length);

			PHP_UV_FS_ASYNC(loop, read, fd, &buf, 1, offset);
			break;
		}
		case UV_FS_SENDFILE:
		{
			zval *z_instream, *z_outstream = NULL;
			unsigned long in_fd, out_fd;
			zend_long offset, length = 0;

			PHP_UV_FS_PARSE_PARAMETERS(4, Z_PARAM_RESOURCE(z_instream) Z_PARAM_RESOURCE(z_outstream) Z_PARAM_LONG(offset) Z_PARAM_LONG(length));
			PHP_UV_FS_SETUP()
			/* TODO */
			PHP_UV_ZVAL_TO_FD(in_fd, z_instream);
			PHP_UV_ZVAL_TO_FD(out_fd, z_outstream);
			uv->fs_fd = *z_outstream;
			Z_ADDREF(uv->fs_fd);
			uv->fs_fd_alt = *z_instream;
			Z_ADDREF(uv->fs_fd_alt);
			PHP_UV_FS_ASYNC(loop, sendfile, in_fd, out_fd, offset, length);
			break;
		}
		case UV_FS_WRITE:
		{
			zval *zstream = NULL;
			zend_string *buffer;
			zend_long fd, offset = -1;
			uv_buf_t uv_fs_write_buf_t;

			ZEND_PARSE_PARAMETERS_START(3, 5)
				UV_PARAM_OBJ(loop, php_uv_loop_t, uv_loop_ce)
				Z_PARAM_RESOURCE(zstream)
				Z_PARAM_STR(buffer)
				Z_PARAM_OPTIONAL
				Z_PARAM_LONG(offset)
				Z_PARAM_FUNC_EX(fci, fcc, 1, 0)
			ZEND_PARSE_PARAMETERS_END();
			PHP_UV_FS_SETUP();
			PHP_UV_ZVAL_TO_FD(fd, zstream);
			uv->fs_fd = *zstream;
			Z_ADDREF(uv->fs_fd);
			uv->buffer = estrndup(buffer->val, buffer->len);

			/* TODO: is this right?! */
			uv_fs_write_buf_t = uv_buf_init(uv->buffer, buffer->len);
			PHP_UV_FS_ASYNC(loop, write, fd, &uv_fs_write_buf_t, 1, offset);
			break;
		}
		case UV_FS_UNKNOWN:
		case UV_FS_CUSTOM:
		default: {
			php_error_docref(NULL, E_ERROR, "type; %d does not support yet.", fs_type);
			break;
		}
	}

#undef PHP_UV_FS_PARSE_PARAMETERS
#undef PHP_UV_FS_SETUP
#undef PHP_UV_FS_SETUP_AND_EXECUTE

}
/* util */

static zval php_uv_address_to_zval(const struct sockaddr *addr)
{
	zval tmp = {0};
	char ip[INET6_ADDRSTRLEN];
	const struct sockaddr_in *a4;
	const struct sockaddr_in6 *a6;
	int port;

	array_init(&tmp);

	switch (addr->sa_family) {
		case AF_INET6:
		{
			a6 = (const struct sockaddr_in6 *)addr;
			uv_inet_ntop(AF_INET, &a6->sin6_addr, ip, sizeof ip);
			port = ntohs(a6->sin6_port);

			add_assoc_string_ex(&tmp, ZEND_STRL("address"), ip);
			add_assoc_long_ex(&tmp, ZEND_STRL("port"), port);
			add_assoc_string_ex(&tmp, ZEND_STRL("family"), "IPv6");
			break;
		}
		case AF_INET:
		{
			a4 = (const struct sockaddr_in *)addr;
			uv_inet_ntop(AF_INET, &a4->sin_addr, ip, sizeof ip);
			port = ntohs(a4->sin_port);

			add_assoc_string_ex(&tmp, ZEND_STRL("address"), ip);
			add_assoc_long_ex(&tmp, ZEND_STRL("port"), port);
			add_assoc_string_ex(&tmp, ZEND_STRL("family"), "IPv4");
			break;
		}
		default:
		break;
	}

	return tmp;
}

static zval php_uv_make_stat(const uv_stat_t *s)
{
	zval tmp = {0};
	array_init(&tmp);

	add_assoc_long_ex(&tmp, ZEND_STRL("dev"), s->st_dev);
	add_assoc_long_ex(&tmp, ZEND_STRL("ino"), s->st_ino);
	add_assoc_long_ex(&tmp, ZEND_STRL("mode"), s->st_mode);
	add_assoc_long_ex(&tmp, ZEND_STRL("nlink"), s->st_nlink);
	add_assoc_long_ex(&tmp, ZEND_STRL("uid"), s->st_uid);
	add_assoc_long_ex(&tmp, ZEND_STRL("gid"), s->st_gid);
	add_assoc_long_ex(&tmp, ZEND_STRL("rdev"), s->st_rdev);
	add_assoc_long_ex(&tmp, ZEND_STRL("size"), s->st_size);

#ifndef PHP_WIN32
	add_assoc_long_ex(&tmp, ZEND_STRL("blksize"), s->st_blksize);
	add_assoc_long_ex(&tmp, ZEND_STRL("blocks"), s->st_blocks);
#endif

	add_assoc_long_ex(&tmp, ZEND_STRL("atime"), s->st_atim.tv_sec);
	add_assoc_long_ex(&tmp, ZEND_STRL("mtime"), s->st_mtim.tv_sec);
	add_assoc_long_ex(&tmp, ZEND_STRL("ctime"), s->st_ctim.tv_sec);

	return tmp;
}

static inline zend_bool php_uv_closeable_type(php_uv_t *uv) {
	zend_class_entry *ce = uv->std.ce;
	return ce == uv_pipe_ce || ce == uv_tty_ce || ce == uv_tcp_ce || ce == uv_udp_ce || ce == uv_prepare_ce || ce == uv_check_ce || ce == uv_idle_ce || ce == uv_async_ce || ce == uv_timer_ce || ce == uv_process_ce || ce == uv_fs_event_ce || ce == uv_poll_ce || ce == uv_fs_poll_ce || ce == uv_signal_ce;
}

/* destructor */

void static destruct_uv_lock(zend_object *obj)
{
	php_uv_lock_t *lock = (php_uv_lock_t *) obj;

	if (lock->type == IS_UV_RWLOCK) {
		if (lock->locked == 0x01) {
			php_error_docref(NULL, E_NOTICE, "uv_rwlock: still locked resource detected; forcing wrunlock");
			uv_rwlock_wrunlock(PHP_UV_LOCK_RWLOCK_P(lock));
		} else if (lock->locked) {
			php_error_docref(NULL, E_NOTICE, "uv_rwlock: still locked resource detected; forcing rdunlock");
			while (--lock->locked > 0) {
				uv_rwlock_rdunlock(PHP_UV_LOCK_RWLOCK_P(lock));
			}
		}
		uv_rwlock_destroy(PHP_UV_LOCK_RWLOCK_P(lock));
	} else if (lock->type == IS_UV_MUTEX) {
		if (lock->locked == 0x01) {
			php_error_docref(NULL, E_NOTICE, "uv_mutex: still locked resource detected; forcing unlock");
			uv_mutex_unlock(PHP_UV_LOCK_MUTEX_P(lock));
		}
		uv_mutex_destroy(PHP_UV_LOCK_MUTEX_P(lock));
	} else if (lock->type == IS_UV_SEMAPHORE) {
		if (lock->locked == 0x01) {
			php_error_docref(NULL, E_NOTICE, "uv_sem: still locked resource detected; forcing unlock");
			uv_sem_post(PHP_UV_LOCK_SEM_P(lock));
		}
		uv_sem_destroy(PHP_UV_LOCK_SEM_P(lock));
	}
}

static void destruct_uv_loop_walk_cb(uv_handle_t* handle, void* arg)
{
	php_uv_t *uv = (php_uv_t *) handle->data;
	if (!PHP_UV_IS_DTORED(uv)) { // otherwise we're already closing
		php_uv_close(uv);
	}
}

void static destruct_uv_loop(zend_object *obj)
{
	php_uv_loop_t *loop_obj = (php_uv_loop_t *) obj;
	uv_loop_t *loop = &loop_obj->loop;
	if (loop_obj != UV_G(default_loop)) {
		uv_stop(loop); /* in case we haven't stopped the loop yet otherwise ... */
		uv_run(loop, UV_RUN_DEFAULT); /* invalidate the stop ;-) */

		/* for proper destruction: close all handles, let libuv call close callback and then close and free the loop */
		uv_walk(loop, destruct_uv_loop_walk_cb, NULL);
		uv_run(loop, UV_RUN_DEFAULT);
	}
}

void static free_uv_loop(zend_object *obj)
{
	php_uv_loop_t *loop_obj = (php_uv_loop_t *) obj;
	if (loop_obj != UV_G(default_loop)) {
		uv_loop_close(&loop_obj->loop);
	}
	if (loop_obj->gc_buffer) {
		efree(loop_obj->gc_buffer);
	}
}

void static clean_uv_handle(php_uv_t *uv) {
	int i;

	/* for now */
	for (i = 0; i < PHP_UV_CB_MAX; i++) {
		php_uv_cb_t *cb = uv->callback[i];
		if (cb != NULL) {
			if (ZEND_FCI_INITIALIZED(cb->fci)) {
				zval_dtor(&cb->fci.function_name);

				if (cb->fci.object != NULL) {
					OBJ_RELEASE(cb->fci.object);
				}
			}

			efree(cb);
			cb = NULL;
		}
	}

	PHP_UV_SKIP_DTOR(uv);

	if (!Z_ISUNDEF(uv->fs_fd)) {
		zval_ptr_dtor(&uv->fs_fd);
		ZVAL_UNDEF(&uv->fs_fd);
		if (!Z_ISUNDEF(uv->fs_fd_alt)) {
			zval_ptr_dtor(&uv->fs_fd_alt);
			ZVAL_UNDEF(&uv->fs_fd_alt);
		}
	}
}

void static destruct_uv(zend_object *obj)
{
	php_uv_t *uv = (php_uv_t *) obj;

	PHP_UV_DEBUG_PRINT("# will be free: (obj: %p)\n", obj);

	if (!php_uv_closeable_type(uv)) {
		if (uv_cancel(&uv->uv.req) == UV_EBUSY) {
			GC_ADDREF(obj);
		}
		clean_uv_handle(uv);
	} else {
		php_uv_close(uv);
		/* cleaning happens in close_cb */
	}
}

void static php_uv_free_write_req(write_req_t *wr) {
	if (wr->cb) {
		if (ZEND_FCI_INITIALIZED(wr->cb->fci)) {
			zval_ptr_dtor(&wr->cb->fci.function_name);
			if (wr->cb->fci.object != NULL) {
				OBJ_RELEASE(wr->cb->fci.object);
			}
		}

		efree(wr->cb);
	}
	if (wr->buf.base) {
		efree(wr->buf.base);
	}
	efree(wr);
}

/* callback */
static int php_uv_do_callback(zval *retval_ptr, php_uv_cb_t *callback, zval *params, int param_count TSRMLS_DC)
{
	int error;

#if defined(ZTS) && PHP_VERSION_ID < 80000
	void *old = tsrm_set_interpreter_context(tsrm_ls);
#endif

	if (ZEND_FCI_INITIALIZED(callback->fci)) {
		callback->fci.params = params;
		callback->fci.retval = retval_ptr;
		callback->fci.param_count = param_count;
#if PHP_VERSION_ID < 80000
		callback->fci.no_separation = 1;
#endif

		error = zend_call_function(&callback->fci, &callback->fcc);
	} else {
		error = -1;
	}

#if defined(ZTS) && PHP_VERSION_ID < 80000
	tsrm_set_interpreter_context(old);
#endif

	return error;
}

static int php_uv_do_callback2(zval *retval_ptr, php_uv_t *uv, zval *params, int param_count, enum php_uv_callback_type type TSRMLS_DC)
{
	int error = 0;

#if defined(ZTS) && PHP_VERSION_ID < 80000
	void *old = tsrm_set_interpreter_context(tsrm_ls);
#endif
	if (ZEND_FCI_INITIALIZED(uv->callback[type]->fci)) {
		uv->callback[type]->fci.params        = params;
		uv->callback[type]->fci.retval        = retval_ptr;
		uv->callback[type]->fci.param_count   = param_count;
#if PHP_VERSION_ID < 80000
		uv->callback[type]->fci.no_separation = 1;
#endif

		if (zend_call_function(&uv->callback[type]->fci, &uv->callback[type]->fcc) != SUCCESS) {
			error = -1;
		}
	} else {
		error = -2;
	}

#if defined(ZTS) && PHP_VERSION_ID < 80000
	tsrm_set_interpreter_context(old);
#endif
	//zend_fcall_info_args_clear(&uv->callback[type]->fci, 0);

	if (EG(exception)) {
		switch (type) {
			case PHP_UV_FS_CB:
				uv_stop(uv->uv.fs.loop);
				break;
			case PHP_UV_GETADDR_CB:
				uv_stop(uv->uv.addrinfo.loop);
				break;
			case PHP_UV_AFTER_WORK_CB:
				uv_stop(uv->uv.work.loop);
				break;
			case PHP_UV_SHUTDOWN_CB:
				uv_stop(uv->uv.shutdown.handle->loop);
				break;
			case PHP_UV_SEND_CB:
				uv_stop(uv->uv.udp_send.handle->loop);
				break;
			case PHP_UV_CONNECT_CB:
			case PHP_UV_PIPE_CONNECT_CB:
				uv_stop(uv->uv.connect.handle->loop);
				break;
			default:
				uv_stop(uv->uv.handle.loop);
		}
	}

	return error;
}

#if defined(ZTS) && PHP_VERSION_ID < 80000

static int php_uv_do_callback3(zval *retval_ptr, php_uv_t *uv, zval *params, int param_count, enum php_uv_callback_type type)
{
	int error = 0;
	void *tsrm_ls, *old;
	zend_op_array *ops;
	zend_function fn, *old_fn;

	if (ZEND_FCI_INITIALIZED(uv->callback[type]->fci)) {
		tsrm_ls = tsrm_new_interpreter_context();
		old = tsrm_set_interpreter_context(tsrm_ls);

		PG(expose_php) = 0;
		PG(auto_globals_jit) = 0;

		php_request_startup();
		EG(current_execute_data) = NULL;
		EG(current_module) = phpext_uv_ptr;

		uv->callback[type]->fci.params        = params;
		uv->callback[type]->fci.retval        = retval_ptr;
		uv->callback[type]->fci.param_count   = param_count;
#if PHP_VERSION_ID < 80000
		uv->callback[type]->fci.no_separation = 1;
#endif
		uv->callback[type]->fci.object = NULL;
#if PHP_VERSION_ID >= 70300
		uv->callback[type]->fci.size = sizeof(zend_fcall_info);
#else
		uv->callback[type]->fcc.initialized = 1;
#endif

		uv->callback[type]->fcc.calling_scope = NULL;
		uv->callback[type]->fcc.called_scope = NULL;
		uv->callback[type]->fcc.object = NULL;

		if (!ZEND_USER_CODE(uv->callback[type]->fcc.function_handler->type)) {
			return error = -2;
		}

		fn = *(old_fn = uv->callback[type]->fcc.function_handler);
		uv->callback[type]->fcc.function_handler = &fn;

		ops = &fn.op_array;
#if PHP_VERSION_ID < 70400
		ops->run_time_cache = NULL;
#else
		ZEND_MAP_PTR_SET(ops->run_time_cache, NULL);
#endif
		if (ops->fn_flags) {
			ops->fn_flags &= ~ZEND_ACC_CLOSURE;
			ops->prototype = NULL;
		}

		zend_try {
			if (zend_call_function(&uv->callback[type]->fci, &uv->callback[type]->fcc) != SUCCESS) {
				error = -1;
			}
		} zend_catch {
			error = -1;
		} zend_end_try();

		// after PHP 7.4 this is arena allocated and automatically freed
#if PHP_VERSION_ID < 70400
		if (ops->run_time_cache && !ops->function_name) {
			efree(ops->run_time_cache);
		}
#endif

		uv->callback[type]->fcc.function_handler = old_fn;

		php_request_shutdown(NULL);
		tsrm_set_interpreter_context(old);
		tsrm_free_interpreter_context(tsrm_ls);
	} else {
		error = -2;
	}

	//zend_fcall_info_args_clear(&uv->callback[type]->fci, 0);

	return error;
}
#endif

static void php_uv_tcp_connect_cb(uv_connect_t *req, int status)
{
	zval retval = {0};
	zval params[2] = {0};
	php_uv_t *uv = (php_uv_t *) req->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	ZVAL_OBJ(&params[0], &uv->std);
	ZVAL_LONG(&params[1], status);

	php_uv_do_callback2(&retval, uv, params, 2, PHP_UV_CONNECT_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_udp_tcp_cb, uv);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);

	zval_ptr_dtor(&retval);
	efree(req);
}

static void php_uv_process_close_cb(uv_process_t* process, int64_t exit_status, int term_signal)
{
	zval retval = {0};
	zval params[3] = {0};
	php_uv_t *uv = (php_uv_t *) process->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	ZVAL_OBJ(&params[0], &uv->std);
	ZVAL_LONG(&params[1], exit_status);
	ZVAL_LONG(&params[2], term_signal);

	php_uv_do_callback2(&retval, uv, params, 3, PHP_UV_PROC_CLOSE_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_process_close_cb, uv);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);
	zval_ptr_dtor(&params[2]);

	zval_ptr_dtor(&retval);
}


static void php_uv_pipe_connect_cb(uv_connect_t *req, int status)
{
	zval retval = {0};
	zval params[2] = {0};
	php_uv_t *uv = (php_uv_t*)req->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	ZVAL_OBJ(&params[0], &uv->std);
	ZVAL_LONG(&params[1], status);

	php_uv_do_callback2(&retval, uv, params, 2, PHP_UV_PIPE_CONNECT_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_pipe_connect_cb, uv);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);

	zval_ptr_dtor(&retval);
	efree(req);
}


static void php_uv_walk_cb(uv_handle_t* handle, void* arg)
{
/*
	zval retval = {0};
	zval params[2] = {0};
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	ZVAL_LONG(&params[0], status);
	ZVAL_OBJ(&params[1], &uv->std);

	php_uv_do_callback2(&retval, uv, params, 2, PHP_UV_PIPE_CONNECT_CB TSRMLS_CC);

	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);
	zval_ptr_dtor(&retval);
	efree(req);
*/
}

static void php_uv_write_cb(uv_write_t* req, int status)
{
	write_req_t* wr = (write_req_t*) req;
	zval retval = {0};
	zval params[2] = {0};
	php_uv_t *uv = (php_uv_t *) req->handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("uv_write_cb: status: %d\n", status);

	ZVAL_OBJ(&params[0], &uv->std);
	ZVAL_LONG(&params[1], status);

	php_uv_do_callback(&retval, wr->cb, params, 2 TSRMLS_CC);

	if (EG(exception)) {
		uv_stop(uv->uv.handle.loop);
	}

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_write_cb, uv);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);

	zval_ptr_dtor(&retval);

	php_uv_free_write_req(wr);
}

static void php_uv_udp_send_cb(uv_udp_send_t* req, int status)
{
	send_req_t* wr = (send_req_t*) req;
	zval retval = {0};
	zval params[2] = {0};
	php_uv_t *uv = (php_uv_t *) req->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	ZVAL_OBJ(&params[0], &uv->std);
	ZVAL_LONG(&params[1], status);

	php_uv_do_callback2(&retval, uv, params, 2, PHP_UV_SEND_CB TSRMLS_CC);

	if (!uv_is_closing(&uv->uv.handle)) { /* send_cb is invoked *before* the handle is marked as inactive - uv_close() will thus *not* increment the refcount and we must then not delete the refcount here */
		PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_udp_send_cb, uv);
		zval_ptr_dtor(&params[0]);
	}
	zval_ptr_dtor(&params[1]);

	zval_ptr_dtor(&retval);

	if (wr->buf.base) {
		efree(wr->buf.base);
	}
	efree(wr);
}

static void php_uv_listen_cb(uv_stream_t* server, int status)
{
	zval retval = {0};
	zval params[2] = {0};
	php_uv_t *uv = (php_uv_t *) server->data;

	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	ZVAL_OBJ(&params[0], &uv->std);
	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_listen_cb, uv);
	ZVAL_LONG(&params[1], status);

	php_uv_do_callback2(&retval, uv, params, 2, PHP_UV_LISTEN_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_listen_cb, uv);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);

	zval_ptr_dtor(&retval);
}

static void php_uv_shutdown_cb(uv_shutdown_t* handle, int status)
{
	zval retval = {0};
	zval params[2] = {0};
	php_uv_t *uv = (php_uv_t *) handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	ZVAL_OBJ(&params[0], &uv->std);
	ZVAL_LONG(&params[1], status);

	php_uv_do_callback2(&retval, uv, params, 2, PHP_UV_SHUTDOWN_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_shutdown_cb, uv);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);

	zval_ptr_dtor(&retval);
}

static void php_uv_read_cb(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf)
{
	zval retval = {0};
	zval params[2] = {0};
	php_uv_t *uv = (php_uv_t *) handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("uv_read_cb\n");

	ZVAL_OBJ(&params[0], &uv->std);
	if (nread > 0) { // uv disables itself when it reaches EOF/error
		GC_ADDREF(&uv->std);
		PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_read_cb, uv);
	}

	if (nread > 0) {
		ZVAL_STRINGL(&params[1], buf->base, nread);
	} else {
		ZVAL_LONG(&params[1], nread);
	}

	php_uv_do_callback2(&retval, uv, params, 2, PHP_UV_READ_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_read_cb, uv);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);

	zval_ptr_dtor(&retval);

	if (buf->base) {
		efree(buf->base);
	}
}

/* unused
static void php_uv_read2_cb(uv_pipe_t* handle, ssize_t nread, uv_buf_t buf, uv_handle_type pending)
{
	zval retval = {0};
	zval params[3] = {0};
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("uv_read2_cb\n");

	ZVAL_OBJ(&params[0], &uv->std);
	if (nread > 0) { // uv disables itself when it reaches EOF/error
		GC_ADDREF(&uv->std);
		PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_read2_cb, uv);
	}
	if (nread > 0) {
		ZVAL_STRINGL(&params[1], buf.base,nread);
	} else {
		ZVAL_LONG(&params[1], nread);
	}
	ZVAL_LONG(&params[2], pending);

	php_uv_do_callback2(&retval, uv, params, 3, PHP_UV_READ2_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_read2_cb, uv);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);
	zval_ptr_dtor(&params[2]);

	zval_ptr_dtor(&retval);

	if (buf.base) {
		efree(buf.base);
	}
}
*/

static void php_uv_prepare_cb(uv_prepare_t* handle)
{
	zval retval = {0};
	zval params[1];
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("prepare_cb\n");

	ZVAL_OBJ(&params[0], &uv->std);
	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_prepare_cb, uv);

	php_uv_do_callback2(&retval, uv, params, 1, PHP_UV_PREPARE_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_prepare_cb, uv);
	zval_ptr_dtor(&params[0]);

	zval_ptr_dtor(&retval);
}

static void php_uv_check_cb(uv_check_t* handle)
{
	zval retval = {0};
	zval params[1];
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("check_cb\n");

	ZVAL_OBJ(&params[0], &uv->std);
	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_check_cb, uv);

	php_uv_do_callback2(&retval, uv, params, 1, PHP_UV_CHECK_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_check_cb, uv);
	zval_ptr_dtor(&params[0]);

	zval_ptr_dtor(&retval);
}


static void php_uv_async_cb(uv_async_t* handle)
{
	zval retval = {0};
	zval params[1];
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("async_cb\n");

	ZVAL_OBJ(&params[0], &uv->std);
	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_async_cb, uv);

	php_uv_do_callback2(&retval, uv, params, 1, PHP_UV_ASYNC_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_async_cb, uv);
	zval_ptr_dtor(&params[0]);

	zval_ptr_dtor(&retval);
}

#if defined(ZTS) && PHP_VERSION_ID < 80000
static void php_uv_work_cb(uv_work_t* req)
{
	zval retval = {0};
	php_uv_t *uv = (php_uv_t*)req->data;

	uv = (php_uv_t*)req->data;

	PHP_UV_DEBUG_PRINT("work_cb\n");

	php_uv_do_callback3(&retval, uv, NULL, 0, PHP_UV_WORK_CB);
}

static void php_uv_after_work_cb(uv_work_t* req, int status)
{
	zval retval = {0};
	php_uv_t *uv = (php_uv_t*)req->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	uv = (php_uv_t*)req->data;

	PHP_UV_DEBUG_PRINT("after_work_cb\n");

	php_uv_do_callback2(&retval, uv, NULL, 0, PHP_UV_AFTER_WORK_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_after_work_cb, uv);

	/* as uv_cancel inside destruct_uv will return EBUSY here as were still in the work callback, but freeing is safe here */
	clean_uv_handle(uv); /* this avoids a cancel */
	OBJ_RELEASE(&uv->std);
}
#endif

static void php_uv_fs_cb(uv_fs_t* req)
{
	zval params[3] = {0};
	zval retval = {0};
	php_uv_t *uv = (php_uv_t*)req->data;
	int argc, i = 0;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("# php_uv_fs_cb %p\n", uv);

	if (PHP_UV_IS_DTORED(uv)) {
		uv_fs_req_cleanup(req);

		OBJ_RELEASE(&uv->std);
		return;
	}

	if (!Z_ISUNDEF(uv->fs_fd)) {
		ZVAL_COPY_VALUE(&params[0], &uv->fs_fd);
		ZVAL_UNDEF(&uv->fs_fd);
	}

	switch (uv->uv.fs.fs_type) {
		case UV_FS_SYMLINK:
		case UV_FS_LINK:
		case UV_FS_CHMOD:
		case UV_FS_RENAME:
		case UV_FS_UNLINK:
		case UV_FS_RMDIR:
		case UV_FS_MKDIR:
		case UV_FS_CLOSE:
		case UV_FS_CHOWN:
		case UV_FS_UTIME:
		case UV_FS_FUTIME:
			argc = 1;
			ZVAL_LONG(&params[0], uv->uv.fs.result);
			break;

		case UV_FS_FCHMOD:
		case UV_FS_FCHOWN:
		case UV_FS_FTRUNCATE:
		case UV_FS_FDATASYNC:
		case UV_FS_FSYNC:
			argc = 2;
			ZVAL_LONG(&params[1], uv->uv.fs.result);
			break;

		case UV_FS_OPEN:
			argc = 1;
			if (uv->uv.fs.result < 0) {
				ZVAL_LONG(&params[0], uv->uv.fs.result);
			} else {
				PHP_UV_FD_TO_ZVAL(&params[0], uv->uv.fs.result)
				PHP_UV_DEBUG_PRINT("Creating fs handle %p\n", Z_RES(params[0]));
			}
			break;

		case UV_FS_SCANDIR:
			argc = 1;
			if (uv->uv.fs.result < 0) { /* req->ptr may be NULL here, but uv_fs_scandir_next() knows to handle it */
				ZVAL_LONG(&params[0], uv->uv.fs.result);
			} else {
				uv_dirent_t dent;

				array_init(&params[0]);
				while (UV_EOF != uv_fs_scandir_next(req, &dent)) {
					add_next_index_string(&params[0], dent.name);
				}
			}
			break;

		case UV_FS_LSTAT:
		case UV_FS_STAT:
			argc = 1;
			if (req->ptr != NULL) {
				params[0] = php_uv_make_stat((const uv_stat_t *) req->ptr);
			} else {
				ZVAL_LONG(&params[0], uv->uv.fs.result);
			}
			break;
		case UV_FS_FSTAT:
			argc = 2;
			if (req->ptr != NULL) {
				params[1] = php_uv_make_stat((const uv_stat_t *) req->ptr);
			} else {
				ZVAL_LONG(&params[1], uv->uv.fs.result);
			}
			break;

		case UV_FS_READLINK:
			argc = 1;
			if (uv->uv.fs.result == 0) {
				ZVAL_STRING(&params[0], req->ptr);
			} else {
				ZVAL_LONG(&params[0], uv->uv.fs.result);
			}
			break;

		case UV_FS_READ:
			argc = 2;
			if (uv->uv.fs.result >= 0) {
				ZVAL_STRINGL(&params[1], uv->buffer, uv->uv.fs.result);
			} else {
				ZVAL_LONG(&params[1], uv->uv.fs.result);
			}
			efree(uv->buffer);
			break;

		case UV_FS_SENDFILE:
			argc = 2;
			ZVAL_LONG(&params[1], uv->uv.fs.result);
			break;

		case UV_FS_WRITE:
			argc = 2;
			ZVAL_LONG(&params[1], uv->uv.fs.result);
			efree(uv->buffer);
			break;

		case UV_FS_UNKNOWN:
		case UV_FS_CUSTOM:
		default:
			argc = 0;
			php_error_docref(NULL, E_ERROR, "type; %d does not support yet.", uv->uv.fs.fs_type);
			break;
	}

	php_uv_do_callback2(&retval, uv, params, argc, PHP_UV_FS_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_fs_cb, uv);
	for (i = 0; i < argc; i++) {
		zval_ptr_dtor(&params[i]);
	}

	zval_ptr_dtor(&retval);

	if (!Z_ISUNDEF(uv->fs_fd_alt)) {
		zval_ptr_dtor(&uv->fs_fd_alt);
		ZVAL_UNDEF(&uv->fs_fd_alt);
	}

	uv_fs_req_cleanup(req);

	clean_uv_handle(uv);
	OBJ_RELEASE(&uv->std);
}

static void php_uv_fs_event_cb(uv_fs_event_t* req, const char* filename, int events, int status)
{
	zval params[4] = {0};
	zval retval = {0};
	php_uv_t *uv = (php_uv_t*)req->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	PHP_UV_DEBUG_PRINT("fs_event_cb: %s, %d\n", filename, status);

	ZVAL_OBJ(&params[0], &uv->std);
	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_fs_event_cb, uv);
	if (filename) {
		ZVAL_STRING(&params[1], filename);
	} else {
		ZVAL_NULL(&params[1]);
	}
	ZVAL_LONG(&params[2], events);
	ZVAL_LONG(&params[3], status);

	php_uv_do_callback2(&retval, uv, params, 4, PHP_UV_FS_EVENT_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_fs_event_cb, uv);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);
	zval_ptr_dtor(&params[2]);
	zval_ptr_dtor(&params[3]);

	zval_ptr_dtor(&retval);
}

static zval php_uv_stat_to_zval(const uv_stat_t *stat)
{
	zval result = {0};
	array_init(&result);

	add_assoc_long_ex(&result, ZEND_STRL("dev"), stat->st_dev);
	add_assoc_long_ex(&result, ZEND_STRL("ino"), stat->st_ino);
	add_assoc_long_ex(&result, ZEND_STRL("mode"), stat->st_mode);
	add_assoc_long_ex(&result, ZEND_STRL("nlink"), stat->st_nlink);
	add_assoc_long_ex(&result, ZEND_STRL("uid"), stat->st_uid);
	add_assoc_long_ex(&result, ZEND_STRL("gid"), stat->st_gid);
	add_assoc_long_ex(&result, ZEND_STRL("rdev"), stat->st_rdev);
	add_assoc_long_ex(&result, ZEND_STRL("size"), stat->st_size);

#ifndef PHP_WIN32
	add_assoc_long_ex(&result, ZEND_STRL("blksize"), stat->st_blksize);
	add_assoc_long_ex(&result, ZEND_STRL("blocks"), stat->st_blocks);
#endif

	add_assoc_long_ex(&result, ZEND_STRL("atime"), stat->st_atim.tv_sec);
	add_assoc_long_ex(&result, ZEND_STRL("mtime"), stat->st_mtim.tv_sec);
	add_assoc_long_ex(&result, ZEND_STRL("ctime"), stat->st_ctim.tv_sec);

	return result;
}

static void php_uv_fs_poll_cb(uv_fs_poll_t* handle, int status, const uv_stat_t* prev, const uv_stat_t* curr)
{
	zval params[4] = {0};
	zval retval = {0};
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	ZVAL_OBJ(&params[0], &uv->std);
	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_fs_poll_cb, uv);
	ZVAL_LONG(&params[1], status);
	params[2] = php_uv_stat_to_zval(prev);
	params[3] = php_uv_stat_to_zval(curr);

	php_uv_do_callback2(&retval, uv, params, 4, PHP_UV_FS_POLL_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_fs_poll_cb, uv);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);
	zval_ptr_dtor(&params[2]);
	zval_ptr_dtor(&params[3]);

	zval_ptr_dtor(&retval);
}

static void php_uv_poll_cb(uv_poll_t* handle, int status, int events)
{
	zval params[4] = {0};
	zval retval = {0};
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	ZVAL_OBJ(&params[0], &uv->std);
	if (status == 0) {
		GC_ADDREF(&uv->std);
	}
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_poll_cb, uv);
	ZVAL_LONG(&params[1], status);
	ZVAL_LONG(&params[2], events);
	if (!Z_ISUNDEF(uv->fs_fd)) {
		ZVAL_COPY(&params[3], &uv->fs_fd);
	} else {
		PHP_UV_FD_TO_ZVAL(&params[3], uv->sock);
	}

	php_uv_do_callback2(&retval, uv, params, 4, PHP_UV_POLL_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_poll_cb, uv);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);
	zval_ptr_dtor(&params[2]);
	zval_ptr_dtor(&params[3]);

	zval_ptr_dtor(&retval);
}


static void php_uv_udp_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
	/* TODO: is this correctly implmented? */
	zval retval = {0};
	zval params[3] = {0};
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	ZVAL_OBJ(&params[0], &uv->std);
	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_udp_recv_cb, uv);
	if (nread < 0) {
		ZVAL_LONG(&params[1], nread);
	} else {
		ZVAL_STRINGL(&params[1], buf->base, nread);
	}
	ZVAL_LONG(&params[2], flags);

	php_uv_do_callback2(&retval, uv, params, 3, PHP_UV_RECV_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_udp_recv_cb, uv);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);
	zval_ptr_dtor(&params[2]);

	zval_ptr_dtor(&retval);

	if (buf->base) {
		efree(buf->base);
	}
}

static void php_uv_read_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	buf->base = emalloc(suggested_size);
	buf->len = suggested_size;
}

static void php_uv_close_cb(uv_handle_t *handle)
{
	zval retval = {0};
	zval params[1] = {0};

	php_uv_t *uv = (php_uv_t *) handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	if (uv->callback[PHP_UV_CLOSE_CB]) {
		ZVAL_OBJ(&params[0], &uv->std);

		php_uv_do_callback2(&retval, uv, params, 1, PHP_UV_CLOSE_CB TSRMLS_CC);
		zval_ptr_dtor(&retval);
	}

	/* manually clean the uv handle as dtor will not be called anymore here */
	clean_uv_handle(uv);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_close_cb, uv);
	OBJ_RELEASE(&uv->std);
}

static inline zend_bool php_uv_is_handle_referenced(php_uv_t *uv) {
	zend_class_entry *ce = uv->std.ce;

	return (ce == uv_signal_ce || ce == uv_timer_ce || ce == uv_idle_ce || ce == uv_udp_ce || ce == uv_tcp_ce || ce == uv_tty_ce || ce == uv_pipe_ce || ce == uv_prepare_ce || ce == uv_check_ce || ce == uv_poll_ce || ce == uv_fs_poll_ce) && uv_is_active(&uv->uv.handle);
}

/* uv handle must not be cleaned or closed before called */
static void php_uv_close(php_uv_t *uv) {
	ZEND_ASSERT(!uv_is_closing(&uv->uv.handle));

	if (!php_uv_is_handle_referenced(uv)) {
		GC_ADDREF(&uv->std);
		PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(php_uv_close, uv);
	}

	uv_close(&uv->uv.handle, php_uv_close_cb);

	PHP_UV_SKIP_DTOR(uv);
}

static void php_uv_idle_cb(uv_timer_t *handle)
{
	zval retval = {0};
	zval params[1] = {0};

	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	ZVAL_OBJ(&params[0], &uv->std);
	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(php_uv_idle_cb, uv);

	php_uv_do_callback2(&retval, uv, params, 1, PHP_UV_IDLE_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(php_uv_idle_cb, uv);
	zval_ptr_dtor(&params[0]);

	zval_ptr_dtor(&retval);
}

static void php_uv_getaddrinfo_cb(uv_getaddrinfo_t* handle, int status, struct addrinfo* res)
{
	zval retval = {0};
	zval params[1] = {0};
	struct addrinfo *address;
	char ip[INET6_ADDRSTRLEN];
	const char *addr;

	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	if (status != 0) {
		ZVAL_LONG(&params[0], status);
	} else {
		array_init(&params[0]);

		address = res;
		while (address) {
			if (address->ai_family == AF_INET) {
				addr = (char*) &((struct sockaddr_in*) address->ai_addr)->sin_addr;
				uv_inet_ntop(address->ai_family, addr, ip, INET6_ADDRSTRLEN);
				add_next_index_string(&params[0], ip);
			}

			address = address->ai_next;
		}

		address = res;
		while (address) {
			if (address->ai_family == AF_INET6) {
				addr = (char*) &((struct sockaddr_in6*) address->ai_addr)->sin6_addr;
				uv_inet_ntop(address->ai_family, addr, ip, INET6_ADDRSTRLEN);
				add_next_index_string(&params[0], ip);
			}

			address = address->ai_next;
		}
	}

	php_uv_do_callback2(&retval, uv, params, 1, PHP_UV_GETADDR_CB TSRMLS_CC);

	zval_ptr_dtor(&retval);
	zval_ptr_dtor(&params[0]);

	uv_freeaddrinfo(res);
	clean_uv_handle(uv);
	OBJ_RELEASE(&uv->std);
}

static void php_uv_timer_cb(uv_timer_t *handle)
{
	zval retval = {0};
	zval params[1] = {0};
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	ZVAL_OBJ(&params[0], &uv->std);

	if (handle->repeat) {
		GC_ADDREF(&uv->std);
		PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(php_uv_timer_cb, uv);
	}

	php_uv_do_callback2(&retval, uv, params, 1, PHP_UV_TIMER_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(php_uv_timer_cb, uv);
	zval_ptr_dtor(&params[0]);

	zval_ptr_dtor(&retval);
}

static void php_uv_signal_cb(uv_signal_t *handle, int sig_num)
{
	zval retval = {0};
	zval params[2] = {0};
	php_uv_t *uv = (php_uv_t*)handle->data;
	TSRMLS_FETCH_FROM_CTX(uv->thread_ctx);

	ZVAL_OBJ(&params[0], &uv->std);
	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(php_uv_signal_cb, uv);
	ZVAL_LONG(&params[1], sig_num);

	php_uv_do_callback2(&retval, uv, params, 2, PHP_UV_SIGNAL_CB TSRMLS_CC);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(php_uv_signal_cb, uv);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[1]);

	zval_ptr_dtor(&retval);
}

void static destruct_uv_stdio(zend_object *obj)
{
	php_uv_stdio_t *stdio = (php_uv_stdio_t *) obj;

	zval_ptr_dtor(&stdio->stream);
}


/* common functions */

static void php_uv_ip_common(int ip_type, INTERNAL_FUNCTION_PARAMETERS)
{
	php_uv_sockaddr_t *addr;
	char ip[INET6_ADDRSTRLEN];

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(addr, php_uv_sockaddr_t, (ip_type == 1) ? uv_sockaddr_ipv4_ce : uv_sockaddr_ipv6_ce)
	ZEND_PARSE_PARAMETERS_END();

	if (ip_type == 1) {
		uv_ip4_name(PHP_UV_SOCKADDR_IPV4_P(addr), ip, INET6_ADDRSTRLEN);
	} else {
		uv_ip6_name(PHP_UV_SOCKADDR_IPV6_P(addr), ip, INET6_ADDRSTRLEN);
	}
	RETVAL_STRING(ip);
}

static void php_uv_socket_bind(enum php_uv_socket_type ip_type, INTERNAL_FUNCTION_PARAMETERS)
{
	php_uv_sockaddr_t *addr;
	php_uv_t *uv;
	zend_long flags = 0;
	int r;

	if (ip_type & PHP_UV_UDP) {
		ZEND_PARSE_PARAMETERS_START(2, 3)
			UV_PARAM_OBJ(uv, php_uv_t, uv_udp_ce)
			UV_PARAM_OBJ(addr, php_uv_sockaddr_t, (ip_type == PHP_UV_UDP_IPV4) ? uv_sockaddr_ipv4_ce : uv_sockaddr_ipv6_ce)
			Z_PARAM_OPTIONAL
			Z_PARAM_LONG(flags)
		ZEND_PARSE_PARAMETERS_END();
	} else {
		ZEND_PARSE_PARAMETERS_START(2, 2)
			UV_PARAM_OBJ(uv, php_uv_t, uv_tcp_ce)
			UV_PARAM_OBJ(addr, php_uv_sockaddr_t, (ip_type == PHP_UV_TCP_IPV4) ? uv_sockaddr_ipv4_ce : uv_sockaddr_ipv6_ce)
		ZEND_PARSE_PARAMETERS_END();
	}

	switch (ip_type) {
		case PHP_UV_TCP_IPV4:
			r = uv_tcp_bind((uv_tcp_t*)&uv->uv.tcp, (const struct sockaddr*)&PHP_UV_SOCKADDR_IPV4(addr), 0);
			break;
		case PHP_UV_TCP_IPV6:
			r = uv_tcp_bind((uv_tcp_t*)&uv->uv.tcp, (const struct sockaddr*)&PHP_UV_SOCKADDR_IPV6(addr), 0);
			break;
		case PHP_UV_UDP_IPV4:
			r = uv_udp_bind((uv_udp_t*)&uv->uv.udp, (const struct sockaddr*)&PHP_UV_SOCKADDR_IPV4(addr), flags);
			break;
		case PHP_UV_UDP_IPV6:
			r = uv_udp_bind((uv_udp_t*)&uv->uv.udp, (const struct sockaddr*)&PHP_UV_SOCKADDR_IPV6(addr), flags);
			break;
		default:
			php_error_docref(NULL, E_ERROR, "unhandled type");
			return;
	}

	if (r) {
		php_error_docref(NULL, E_WARNING, "bind failed");
		RETURN_FALSE;
	} else {
		RETURN_TRUE;
	}
}

static void php_uv_socket_getname(int type, INTERNAL_FUNCTION_PARAMETERS)
{
	php_uv_t *uv;
	zval result;
	int addr_len;
	struct sockaddr_storage addr;
	addr_len = sizeof(struct sockaddr_storage);

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, type == 3 ? uv_udp_ce : uv_tcp_ce)
	ZEND_PARSE_PARAMETERS_END();

	switch (type) {
		case 1:
			uv_tcp_getsockname(&uv->uv.tcp, (struct sockaddr*)&addr, &addr_len);
			break;
		case 2:
			uv_tcp_getpeername(&uv->uv.tcp, (struct sockaddr*)&addr, &addr_len);
			break;
		case 3:
			uv_udp_getsockname(&uv->uv.udp, (struct sockaddr*)&addr, &addr_len);
			break;
		default:
			php_error_docref(NULL, E_ERROR, "unexpected type");
		break;
	}

	result = php_uv_address_to_zval((struct sockaddr*)&addr);
	RETURN_ZVAL(&result, 0, 1);
}

static void php_uv_handle_open(int (*open_cb)(uv_handle_t *, long), zend_class_entry *ce, INTERNAL_FUNCTION_PARAMETERS) {
	php_uv_t *uv;
	zval *zstream;
	zend_long fd; // file handle
	int error;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, ce)
		Z_PARAM_ZVAL(zstream)
	ZEND_PARSE_PARAMETERS_END();

	fd = php_uv_zval_to_fd(zstream);
	if (fd < 0) {
		php_error_docref(NULL, E_WARNING, "file descriptor must be unsigned value or a valid resource");
		RETURN_FALSE;
	}

	error = open_cb(&uv->uv.handle, fd);

	if (error) {
		php_error_docref(NULL, E_WARNING, "%s", php_uv_strerror(error));
	}

	RETURN_LONG(error);
}

static void php_uv_udp_send(int type, INTERNAL_FUNCTION_PARAMETERS)
{
	zend_string *data;
	php_uv_t *uv;
	send_req_t *w;
	php_uv_sockaddr_t *addr;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(3, 4)
		UV_PARAM_OBJ(uv, php_uv_t, uv_udp_ce)
		Z_PARAM_STR(data)
		UV_PARAM_OBJ(addr, php_uv_sockaddr_t, (type == 1) ? uv_sockaddr_ipv4_ce : uv_sockaddr_ipv6_ce, uv_sockaddr_ipv6_ce)
		Z_PARAM_OPTIONAL
		Z_PARAM_FUNC_EX(fci, fcc, 1, 0)
	ZEND_PARSE_PARAMETERS_END();

	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_udp_send, uv);

	PHP_UV_INIT_SEND_REQ(w, uv, data->val, data->len);
	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_SEND_CB);

	if (addr->std.ce == uv_sockaddr_ipv4_ce) {
		uv_udp_send(&w->req, &uv->uv.udp, &w->buf, 1, (const struct sockaddr*)&PHP_UV_SOCKADDR_IPV4(addr), php_uv_udp_send_cb);
	} else {
		uv_udp_send(&w->req, &uv->uv.udp, &w->buf, 1, (const struct sockaddr*)&PHP_UV_SOCKADDR_IPV6(addr), php_uv_udp_send_cb);
	}
}

static void php_uv_tcp_connect(enum php_uv_socket_type type, INTERNAL_FUNCTION_PARAMETERS)
{
	php_uv_t *uv;
	php_uv_sockaddr_t *addr;
	uv_connect_t *req;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(2, 3)
		UV_PARAM_OBJ(uv, php_uv_t, uv_tcp_ce)
		UV_PARAM_OBJ(addr, php_uv_sockaddr_t, (type == PHP_UV_TCP_IPV4) ? uv_sockaddr_ipv4_ce : uv_sockaddr_ipv6_ce, uv_sockaddr_ipv6_ce)
		Z_PARAM_OPTIONAL
		Z_PARAM_FUNC_EX(fci, fcc, 1, 0)
	ZEND_PARSE_PARAMETERS_END();

	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_tcp_connect, uv);

	PHP_UV_INIT_CONNECT(req, uv)
	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_CONNECT_CB);

	if (addr->std.ce == uv_sockaddr_ipv4_ce) {
		uv_tcp_connect(req, &uv->uv.tcp, (const struct sockaddr*)&PHP_UV_SOCKADDR_IPV4(addr), php_uv_tcp_connect_cb);
	} else {
		uv_tcp_connect(req, &uv->uv.tcp,  (const struct sockaddr*)&PHP_UV_SOCKADDR_IPV6(addr), php_uv_tcp_connect_cb);
	}
}

/* zend */

static zend_function_entry php_uv_empty_methods[] = {
	{0}
};

#if PHP_VERSION_ID >= 80000
int php_uv_cast_object(zend_object *readobj, zval *writeobj, int type) {
#else
int php_uv_cast_object(zval *readobj_zv, zval *writeobj, int type) {
	zend_object *readobj = Z_OBJ_P(readobj_zv);
#endif
	if (type == IS_LONG) {
		ZVAL_LONG(writeobj, readobj->handle);
		return SUCCESS;
	} else {
#if PHP_VERSION_ID >= 80000
		return zend_std_cast_object_tostring(readobj, writeobj, type);
#else
		return zend_std_cast_object_tostring(readobj_zv, writeobj, type);
#endif
	}
}

#if PHP_VERSION_ID >= 80000
static HashTable *php_uv_get_debug_info(zend_object *object, int *is_temp) {
	php_uv_t *uv = (php_uv_t *) object;
#else
static HashTable *php_uv_get_debug_info(zval *object, int *is_temp) {
	php_uv_t *uv = (php_uv_t *) Z_OBJ_P(object);
#endif
	HashTable *ht = zend_std_get_debug_info(object, is_temp);
	if (uv->std.ce == uv_poll_ce) {
		if (!*is_temp) {
			int fd;
			if (uv_fileno(&uv->uv.handle, (uv_os_fd_t *)&fd) == 0) { /* not actually a fd on windows but a handle pointr address, but okay. */
				*is_temp = 1;
				ht = zend_array_dup(ht);
				zval fdzv;
				ZVAL_LONG(&fdzv, fd);
				zend_hash_update(ht, zend_string_init("@fd", sizeof("@fd")-1, 0), &fdzv);
			}
		}
	}
	return ht;
}

#if PHP_VERSION_ID >= 80000
static HashTable *php_uv_get_gc(zend_object *object, zval **table, int *n) {
	php_uv_t *uv = (php_uv_t *) object;
#else
static HashTable *php_uv_get_gc(zval *object, zval **table, int *n) {
	php_uv_t *uv = (php_uv_t *) Z_OBJ_P(object);
#endif
	int i;

	if (PHP_UV_IS_DTORED(uv)) {
		*n = 0;
		return NULL;
	}

	// include trailing zvals like fs_fd/_alt
	*n = (sizeof(php_uv_t) -  XtOffsetOf(php_uv_t, gc_data)) / sizeof(zval);
	for (i = 0; i < PHP_UV_CB_MAX; i++) {
		php_uv_cb_t *cb = uv->callback[i];
		if (cb) {
			ZVAL_COPY_VALUE(&uv->gc_data[i * 2], &cb->fci.function_name);
			if (cb->fci.object) {
				ZVAL_OBJ(&uv->gc_data[i * 2 + 1], cb->fci.object);
			}
		} else {
			ZVAL_UNDEF(&uv->gc_data[i * 2]);
			ZVAL_UNDEF(&uv->gc_data[i * 2 + 1]);
		}
	}
	*table = uv->gc_data;

	return uv->std.properties;
}

static void php_uv_loop_get_gc_walk_cb(uv_handle_t* handle, void *arg) {
	struct { int *n; php_uv_loop_t *loop; } *data = arg;
	php_uv_t *uv = (php_uv_t *) handle->data;

	if (php_uv_is_handle_referenced(uv)) {
		php_uv_loop_t *loop = data->loop;

		if (*data->n == loop->gc_buffer_size) {
			if (loop->gc_buffer_size == 0) {
				loop->gc_buffer_size = 16;
			} else {
				loop->gc_buffer_size *= 2;
			}
			loop->gc_buffer = erealloc(loop->gc_buffer, loop->gc_buffer_size * sizeof(zval));
		}

		ZVAL_OBJ(loop->gc_buffer + (*data->n)++, &uv->std);
	}
}


#if PHP_VERSION_ID >= 80000
static HashTable *php_uv_loop_get_gc(zend_object *object, zval **table, int *n) {
	php_uv_loop_t *loop = (php_uv_loop_t *) object;
#else
static HashTable *php_uv_loop_get_gc(zval *object, zval **table, int *n) {
	php_uv_loop_t *loop = (php_uv_loop_t *) Z_OBJ_P(object);
#endif
	struct { int *n; php_uv_loop_t *loop; } data;
	data.n = n;
	data.loop = loop;

	*n = 0;
	if (!PHP_UV_IS_DTORED(loop)) {
		uv_walk(&loop->loop, php_uv_loop_get_gc_walk_cb, &data);
		*table = loop->gc_buffer;
	}

	return loop->std.properties;
}

#if PHP_VERSION_ID >= 80000
static HashTable *php_uv_stdio_get_gc(zend_object *object, zval **table, int *n) {
	php_uv_stdio_t *stdio = (php_uv_stdio_t *) object;
#else
static HashTable *php_uv_stdio_get_gc(zval *object, zval **table, int *n) {
	php_uv_stdio_t *stdio = (php_uv_stdio_t *) Z_OBJ_P(object);
#endif

	*n = 1;
	*table = &stdio->stream;

	return stdio->std.properties;
}

static zend_object *php_uv_create_uv(zend_class_entry *ce) {
	php_uv_t *uv = emalloc(sizeof(php_uv_t));
	zend_object_std_init(&uv->std, ce);
	uv->std.handlers = &uv_handlers;

	PHP_UV_INIT_ZVALS(uv);
	TSRMLS_SET_CTX(uv->thread_ctx);

	uv->uv.handle.data = uv;

	return &uv->std;
}

static zend_object *php_uv_create_uv_loop(zend_class_entry *ce) {
	php_uv_loop_t *loop = emalloc(sizeof(php_uv_loop_t));
	zend_object_std_init(&loop->std, ce);
	loop->std.handlers = &uv_loop_handlers;

	uv_loop_init(&loop->loop);

	loop->gc_buffer_size = 0;
	loop->gc_buffer = NULL;

	return &loop->std;
}

static zend_object *php_uv_create_uv_sockaddr(zend_class_entry *ce) {
	php_uv_sockaddr_t *sockaddr = emalloc(sizeof(php_uv_sockaddr_t));
	zend_object_std_init(&sockaddr->std, ce);
	sockaddr->std.handlers = &uv_default_handlers;

	return &sockaddr->std;
}

static zend_object *php_uv_create_uv_lock(zend_class_entry *ce) {
	php_uv_lock_t *lock = emalloc(sizeof(php_uv_lock_t));
	zend_object_std_init(&lock->std, ce);
	lock->std.handlers = &uv_lock_handlers;

	lock->locked = 0;

	return &lock->std;
}

static zend_object *php_uv_create_uv_stdio(zend_class_entry *ce) {
	php_uv_stdio_t *stdio = emalloc(sizeof(php_uv_stdio_t));
	zend_object_std_init(&stdio->std, ce);
	stdio->std.handlers = &uv_stdio_handlers;

	stdio->flags = 0;
	ZVAL_UNDEF(&stdio->stream);

	return &stdio->std;
}

static zend_class_entry *php_uv_register_internal_class_ex(const char *name, zend_class_entry *parent) {
	zend_class_entry ce = {0}, *new;

	ce.name = zend_new_interned_string(zend_string_init(name, strlen(name), 1));
	ce.info.internal.builtin_functions = php_uv_empty_methods;
	new = zend_register_internal_class_ex(&ce, parent);
#if PHP_VERSION_ID < 80100
	new->serialize = zend_class_serialize_deny;
	new->unserialize = zend_class_unserialize_deny;
#endif
	new->ce_flags |= ZEND_ACC_FINAL;
#if PHP_VERSION_ID >= 80100
	new->ce_flags |= ZEND_ACC_NOT_SERIALIZABLE ;
#endif
	new->create_object = php_uv_create_uv;

	return new;
}

static zend_class_entry *php_uv_register_internal_class(const char *name) {
	return php_uv_register_internal_class_ex(name, NULL);
}

static zend_function *php_uv_get_ctor(zend_object *object) {
	zend_throw_error(NULL, "The UV classes cannot be instantiated manually");
	return NULL;
}

PHP_MINIT_FUNCTION(uv)
{
	PHP_UV_PROBE(MINIT);

#if PHP_VERSION_ID >= 70300
	memcpy(&uv_default_handlers, &std_object_handlers, sizeof(zend_object_handlers));
#else
	memcpy(&uv_default_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
#endif
	uv_default_handlers.clone_obj = NULL;
	uv_default_handlers.get_constructor = php_uv_get_ctor;
	uv_default_handlers.cast_object = php_uv_cast_object;

	uv_ce = php_uv_register_internal_class("UV");
	uv_ce->ce_flags |= ZEND_ACC_ABSTRACT;
	uv_ce->ce_flags &= ~ZEND_ACC_FINAL;
	memcpy(&uv_handlers, &uv_default_handlers, sizeof(zend_object_handlers));
	uv_handlers.get_gc = php_uv_get_gc;
	uv_handlers.dtor_obj = destruct_uv;
	uv_handlers.get_debug_info = php_uv_get_debug_info;

	php_uv_init(uv_ce);

	uv_stream_ce = php_uv_register_internal_class_ex("UVStream", uv_ce);
	uv_stream_ce->ce_flags |= ZEND_ACC_ABSTRACT;
	uv_stream_ce->ce_flags &= ~ZEND_ACC_FINAL;

	uv_tcp_ce = php_uv_register_internal_class_ex("UVTcp", uv_stream_ce);
	uv_udp_ce = php_uv_register_internal_class_ex("UVUdp", uv_ce);
	uv_pipe_ce = php_uv_register_internal_class_ex("UVPipe", uv_stream_ce);
	uv_idle_ce = php_uv_register_internal_class_ex("UVIdle", uv_ce);
	uv_timer_ce = php_uv_register_internal_class_ex("UVTimer", uv_ce);
	uv_async_ce = php_uv_register_internal_class_ex("UVAsync", uv_ce);
	uv_addrinfo_ce = php_uv_register_internal_class_ex("UVAddrinfo", uv_ce);
	uv_process_ce = php_uv_register_internal_class_ex("UVProcess", uv_ce);
	uv_prepare_ce = php_uv_register_internal_class_ex("UVPrepare", uv_ce);
	uv_check_ce = php_uv_register_internal_class_ex("UVCheck", uv_ce);
	uv_work_ce = php_uv_register_internal_class_ex("UVWork", uv_ce);
	uv_fs_ce = php_uv_register_internal_class_ex("UVFs", uv_ce);
	uv_fs_event_ce = php_uv_register_internal_class_ex("UVFsEvent", uv_ce);
	uv_tty_ce = php_uv_register_internal_class_ex("UVTty", uv_stream_ce);
	uv_fs_poll_ce = php_uv_register_internal_class_ex("UVFsPoll", uv_ce);
	uv_poll_ce = php_uv_register_internal_class_ex("UVPoll", uv_ce);
	uv_signal_ce = php_uv_register_internal_class_ex("UVSignal", uv_ce);

	uv_loop_ce = php_uv_register_internal_class("UVLoop");
	uv_loop_ce->create_object = php_uv_create_uv_loop;
	memcpy(&uv_loop_handlers, &uv_default_handlers, sizeof(zend_object_handlers));
	uv_loop_handlers.get_gc = php_uv_loop_get_gc;
	uv_loop_handlers.dtor_obj = destruct_uv_loop;
	uv_loop_handlers.free_obj = free_uv_loop;

	uv_sockaddr_ce = php_uv_register_internal_class("UVSockAddr");
	uv_sockaddr_ce->ce_flags |= ZEND_ACC_ABSTRACT;
	uv_sockaddr_ce->ce_flags &= ~ZEND_ACC_FINAL;
	uv_sockaddr_ce->create_object = php_uv_create_uv_sockaddr;

	uv_sockaddr_ipv4_ce = php_uv_register_internal_class_ex("UVSockAddrIPv4", uv_sockaddr_ce);
	uv_sockaddr_ipv4_ce->create_object = php_uv_create_uv_sockaddr;

	uv_sockaddr_ipv6_ce = php_uv_register_internal_class_ex("UVSockAddrIPv6", uv_sockaddr_ce);
	uv_sockaddr_ipv6_ce->create_object = php_uv_create_uv_sockaddr;

	uv_lock_ce = php_uv_register_internal_class("UVLock");
	uv_lock_ce->create_object = php_uv_create_uv_lock;
	memcpy(&uv_lock_handlers, &uv_default_handlers, sizeof(zend_object_handlers));
	uv_lock_handlers.dtor_obj = destruct_uv_lock;

	uv_stdio_ce = php_uv_register_internal_class("UVStdio");
	uv_stdio_ce->create_object = php_uv_create_uv_stdio;
	memcpy(&uv_stdio_handlers, &uv_default_handlers, sizeof(zend_object_handlers));
	uv_stdio_handlers.dtor_obj = destruct_uv_stdio;
	uv_stdio_handlers.get_gc = php_uv_stdio_get_gc;

#if !defined(PHP_WIN32) && !(defined(HAVE_SOCKETS) && !defined(COMPILE_DL_SOCKETS))
	{
		zend_module_entry *sockets;
		if ((sockets = zend_hash_str_find_ptr(&module_registry, ZEND_STRL("sockets")))) {
			if (sockets->handle) { // shared
# if PHP_VERSION_ID >= 80000
				zend_class_entry **socket_ce_ptr = (zend_class_entry **) DL_FETCH_SYMBOL(sockets->handle, "socket_ce");
				if (socket_ce_ptr == NULL) {
					socket_ce_ptr = (zend_class_entry **) DL_FETCH_SYMBOL(sockets->handle, "_socket_ce");
				}
				socket_ce = *socket_ce_ptr;
# else
				php_sockets_le_socket_ptr = (int (*)(void)) DL_FETCH_SYMBOL(sockets->handle, "php_sockets_le_socket");
				if (php_sockets_le_socket_ptr == NULL) {
					php_sockets_le_socket_ptr = (int (*)(void)) DL_FETCH_SYMBOL(sockets->handle, "_php_sockets_le_socket");
				}
			} else {
				php_sockets_le_socket_ptr = &php_sockets_le_socket;
#endif
			}
		}
	}
#endif

	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(uv)
{
	if (UV_G(default_loop)) {
		uv_loop_t *loop = &UV_G(default_loop)->loop;

		/* for proper destruction: close all handles, let libuv call close callback and then close and free the loop */
		uv_stop(loop); /* in case we longjmp()'ed ... */
		uv_run(loop, UV_RUN_DEFAULT); /* invalidate the stop ;-) */

		uv_walk(loop, destruct_uv_loop_walk_cb, NULL);
		uv_run(loop, UV_RUN_DEFAULT);
		uv_loop_close(loop);
		OBJ_RELEASE(&UV_G(default_loop)->std);
	}

	return SUCCESS;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_run, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, run_mode)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_stop, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_loop_delete, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_now, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_connect, 0, 0, 2)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, sock_addr)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_connect6, 0, 0, 2)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, ipv6_addr)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_init, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_listen, 0, 0, 3)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, backlog)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_accept, 0, 0, 2)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, client)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_read_start, 0, 0, 2)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_read_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, server)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_write, 0, 0, 3)
	ZEND_ARG_INFO(0, client)
	ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_write2, 0, 0, 4)
	ZEND_ARG_INFO(0, client)
	ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, send)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_strerror, 0, 0, 1)
	ZEND_ARG_INFO(0, error)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_err_name, 0, 0, 1)
	ZEND_ARG_INFO(0, error)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_init, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_idle_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, idle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_start, 0, 0, 3)
	ZEND_ARG_INFO(0, timer)
	ZEND_ARG_INFO(0, timeout)
	ZEND_ARG_INFO(0, repeat)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, timer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_again, 0, 0, 1)
	ZEND_ARG_INFO(0, timer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_set_repeat, 0, 0, 2)
	ZEND_ARG_INFO(0, timer)
	ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_timer_get_repeat, 0, 0, 1)
	ZEND_ARG_INFO(0, timer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_idle_start, 0, 0, 2)
	ZEND_ARG_INFO(0, timer)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_open, 0, 0, 2)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, tcpfd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_bind, 0, 0, 2)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, address)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_bind6, 0, 0, 2)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, address)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_shutdown, 0, 0, 2)
	ZEND_ARG_INFO(0, stream)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_close, 0, 0, 1)
	ZEND_ARG_INFO(0, stream)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_idle_init, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_update_time, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_is_active, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_is_closing, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_is_readable, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_is_writable, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_walk, 0, 0, 2)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, callback)
	ZEND_ARG_INFO(0, opaque)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_guess_handle, 0, 0, 1)
	ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_ref, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_unref, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_nodelay, 0, 0, 2)
	ZEND_ARG_INFO(0, tcp)
	ZEND_ARG_INFO(0, enabled)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_ip4_addr, 0, 0, 2)
	ZEND_ARG_INFO(0, address)
	ZEND_ARG_INFO(0, port)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_ip6_addr, 0, 0, 2)
	ZEND_ARG_INFO(0, address)
	ZEND_ARG_INFO(0, port)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_init, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_open, 0, 0, 2)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, udpfd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_bind, 0, 0, 2)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, address)
	ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_bind6, 0, 0, 2)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, address)
	ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_recv_start, 0, 0, 2)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_recv_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, server)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_set_multicast_loop, 0, 0, 2)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, enabled)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_set_multicast_ttl, 0, 0, 2)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, ttl)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_set_broadcast, 0, 0, 2)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, enabled)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_send, 0, 0, 3)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, buffer)
	ZEND_ARG_INFO(0, address)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_send6, 0, 0, 3)
	ZEND_ARG_INFO(0, server)
	ZEND_ARG_INFO(0, buffer)
	ZEND_ARG_INFO(0, address)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_pipe_open, 0, 0, 2)
	ZEND_ARG_INFO(0, file)
	ZEND_ARG_INFO(0, pipe)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_pipe_init, 0, 0, 0)
	ZEND_ARG_INFO(0, file)
	ZEND_ARG_INFO(0, ipc)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_pipe_bind, 0, 0, 2)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_pipe_connect, 0, 0, 3)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, name)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_pipe_pending_count, 0, 0, 1)
    ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_pipe_pending_type, 0, 0, 1)
    ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_pipe_pending_instances, 0, 0, 2)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_getaddrinfo, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, callback)
	ZEND_ARG_INFO(0, node)
	ZEND_ARG_INFO(0, service)
	ZEND_ARG_INFO(0, hints)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_spawn, 0, 0, 7)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, command)
	ZEND_ARG_INFO(0, args)
	ZEND_ARG_INFO(0, stdio)
	ZEND_ARG_INFO(0, cwd)
	ZEND_ARG_INFO(0, env)
	ZEND_ARG_INFO(0, callback)
	ZEND_ARG_INFO(0, flags)
	ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_kill, 0, 0, 2)
	ZEND_ARG_INFO(0, pid)
	ZEND_ARG_INFO(0, signal)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_process_kill, 0, 0, 2)
	ZEND_ARG_INFO(0, process)
	ZEND_ARG_INFO(0, signal)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_process_get_pid, 0, 0, 1)
	ZEND_ARG_INFO(0, process)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_chdir, 0, 0, 1)
	ZEND_ARG_INFO(0, dir)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tty_get_winsize, 0, 0, 3)
	ZEND_ARG_INFO(0, tty)
	ZEND_ARG_INFO(1, width)
	ZEND_ARG_INFO(1, height)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tty_init, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, readable)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_event_init, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, callback)
	ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_sendfile, 0, 0, 5)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, in)
	ZEND_ARG_INFO(0, out)
	ZEND_ARG_INFO(0, offset)
	ZEND_ARG_INFO(0, length)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_readdir, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, flags)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_scandir, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, flags)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_fstat, 0, 0, 2)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_lstat, 0, 0, 2)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_stat, 0, 0, 2)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_readlink, 0, 0, 2)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_symlink, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, from)
	ZEND_ARG_INFO(0, to)
	ZEND_ARG_INFO(0, callback)
	ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_link, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, from)
	ZEND_ARG_INFO(0, to)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_fchown, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, uid)
	ZEND_ARG_INFO(0, gid)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_chown, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, uid)
	ZEND_ARG_INFO(0, gid)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_fchmod, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, mode)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_chmod, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, mode)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_futime, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, utime)
	ZEND_ARG_INFO(0, atime)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_utime, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, utime)
	ZEND_ARG_INFO(0, atime)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_open, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, flag)
	ZEND_ARG_INFO(0, mode)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_read, 0, 0, 2)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, offset)
	ZEND_ARG_INFO(0, size)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_close, 0, 0, 2)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_write, 0, 0, 4)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, buffer)
	ZEND_ARG_INFO(0, offset)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_fsync, 0, 0, 2)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_fdatasync, 0, 0, 2)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_ftruncate, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
	ZEND_ARG_INFO(0, offset)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_mkdir, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, mode)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_rmdir, 0, 0, 2)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_unlink, 0, 0, 2)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_rename, 0, 0, 3)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, from)
	ZEND_ARG_INFO(0, to)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_rwlock_rdlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_rwlock_tryrdlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_rwlock_rdunlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_rwlock_wrlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_rwlock_trywrlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_rwlock_wrunlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_mutex_lock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_mutex_trylock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_mutex_unlock, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_sem_init, 0, 0, 1)
	ZEND_ARG_INFO(0, val)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_sem_post, 0, 0, 1)
	ZEND_ARG_INFO(0, resource)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_sem_wait, 0, 0, 1)
	ZEND_ARG_INFO(0, resource)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_sem_trywait, 0, 0, 1)
	ZEND_ARG_INFO(0, resource)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_prepare_init, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_prepare_start, 0, 0, 2)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_prepare_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_check_init, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_check_start, 0, 0, 2)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_check_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_async_send, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_async_init, 0, 0, 2)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_getsockname, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_getpeername, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_getsockname, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_tcp_simultaneous_accepts, 0, 0, 2)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, enable)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_udp_set_membership, 0, 0, 4)
	ZEND_ARG_INFO(0, client)
	ZEND_ARG_INFO(0, multicast_addr)
	ZEND_ARG_INFO(0, interface_addr)
	ZEND_ARG_INFO(0, membership)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_ip6_name, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_ip4_name, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_poll_init, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_poll_start, 0, 0, 4)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, callback)
	ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, interval)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_fs_poll_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_poll_init, 0, 0, 2)
	ZEND_ARG_INFO(0, loop)
	ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_poll_start, 0, 0, 3)
	ZEND_ARG_INFO(0, handle)
	ZEND_ARG_INFO(0, events)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_poll_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_signal_init, 0, 0, 0)
	ZEND_ARG_INFO(0, loop)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_signal_start, 0, 0, 3)
	ZEND_ARG_INFO(0, sig_handle)
	ZEND_ARG_INFO(0, sig_callback)
	ZEND_ARG_INFO(0, sig_num)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_uv_signal_stop, 0, 0, 1)
	ZEND_ARG_INFO(0, sig_handle)
ZEND_END_ARG_INFO()

/* PHP Functions */

/* {{{ proto void uv_unref(UV $uv_t)
*/
PHP_FUNCTION(uv_unref)
{
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_ce)
	ZEND_PARSE_PARAMETERS_END();

	uv_unref(&uv->uv.handle);
}
/* }}} */

/* {{{ proto string uv_err_name(long $error_code)
*/
PHP_FUNCTION(uv_err_name)
{
	zend_long error_code;
	const char *error_msg;

	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"l", &error_code) == FAILURE) {
		return;
	}

	if (error_code < UV_ERRNO_MAX || error_code > 0) {
		php_error_docref(NULL, E_NOTICE, "passes unexpected value.");
		RETURN_FALSE;
	}

	error_msg = uv_err_name(error_code);

	RETVAL_STRING(error_msg);
}
/* }}} */


/* {{{ proto string uv_strerror(long $error_code)
*/
PHP_FUNCTION(uv_strerror)
{
	zend_long error_code;
	const char *error_msg;

	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"l", &error_code) == FAILURE) {
		return;
	}

	error_msg = php_uv_strerror(error_code);
	RETVAL_STRING(error_msg);
}
/* }}} */

/* {{{ proto void uv_update_time([UVLoop $uv_loop = uv_default_loop()])
*/
PHP_FUNCTION(uv_update_time)
{
	php_uv_loop_t *loop = NULL;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		UV_PARAM_OBJ_NULL(loop, php_uv_loop_t, uv_loop_ce)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	uv_update_time(&loop->loop);
}
/* }}} */

/* {{{ proto void uv_ref(UV $uv_handle)
*/
PHP_FUNCTION(uv_ref)
{
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_ce)
	ZEND_PARSE_PARAMETERS_END();

	uv_ref(&uv->uv.handle);
}
/* }}} */

/* {{{ proto void uv_run([UVLoop $uv_loop = uv_default_loop(), long $run_mode = UV::RUN_DEFAULT])
*/
PHP_FUNCTION(uv_run)
{
	php_uv_loop_t *loop = NULL;
	zend_long run_mode = UV_RUN_DEFAULT;

	ZEND_PARSE_PARAMETERS_START(0, 2)
		Z_PARAM_OPTIONAL
		UV_PARAM_OBJ_NULL(loop, php_uv_loop_t, uv_loop_ce)
		Z_PARAM_LONG(run_mode)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	uv_run(&loop->loop, run_mode);
}
/* }}} */

/* {{{ proto void uv_stop([UVLoop $uv_loop = uv_default_loop()])
*/
PHP_FUNCTION(uv_stop)
{
	php_uv_loop_t *loop = NULL;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		UV_PARAM_OBJ_NULL(loop, php_uv_loop_t, uv_loop_ce)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	uv_stop(&loop->loop);
}
/* }}} */

/* {{{ proto resource uv_signal_init([UVLoop $uv_loop = uv_default_loop()])
*/
PHP_FUNCTION(uv_signal_init)
{
	php_uv_loop_t *loop = NULL;
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		UV_PARAM_OBJ_NULL(loop, php_uv_loop_t, uv_loop_ce)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	PHP_UV_INIT_UV_EX(uv, uv_signal_ce, uv_signal_init);

	RETURN_OBJ(&uv->std);
}
/* }}} */

/* {{{ proto void uv_signal_start(UVSignal $sig_handle, callable(UVSignal $sig_handle, long $sig_num) $sig_callback, int $sig_num)
*/
PHP_FUNCTION(uv_signal_start)
{
	zend_long sig_num;
	php_uv_t *uv;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		UV_PARAM_OBJ(uv, php_uv_t, uv_signal_ce)
		Z_PARAM_FUNC(fci, fcc)
		Z_PARAM_LONG(sig_num)
	ZEND_PARSE_PARAMETERS_END();

	if (uv_is_active((uv_handle_t *) &uv->uv.signal)) {
		php_error_docref(NULL, E_NOTICE, "passed uv signal resource has been started. you don't have to call this method");
		RETURN_FALSE;
	}

	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_signal_start, uv);

	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_SIGNAL_CB);

	uv_signal_start((uv_signal_t *) &uv->uv.signal, php_uv_signal_cb, sig_num);
}
/* }}} */

/* {{{ proto int uv_signal_stop(UVSignal $sig_handle)
*/
PHP_FUNCTION(uv_signal_stop)
{
	php_uv_t *uv;
	int r = 0;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_signal_ce)
	ZEND_PARSE_PARAMETERS_END();

	if (!uv_is_active((uv_handle_t *) &uv->uv.signal)) {
		php_error_docref(NULL, E_NOTICE, "passed uv signal resource has been stopped. you don't have to call this method");
		RETURN_FALSE;
	}

	r = uv_signal_stop((uv_signal_t *) &uv->uv.signal);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_signal_stop, uv);
	OBJ_RELEASE(&uv->std);

	RETURN_LONG(r);
}
/* }}} */

/* {{{ proto void uv_loop_delete(UVLoop $uv_loop)
*/
PHP_FUNCTION(uv_loop_delete)
{
	php_uv_loop_t *loop;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(loop, php_uv_loop_t, uv_loop_ce)
	ZEND_PARSE_PARAMETERS_END();

	if (loop != UV_G(default_loop)) {
#if PHP_VERSION_ID < 70300
		GC_FLAGS(&loop->std) |= IS_OBJ_DESTRUCTOR_CALLED;
#else
		GC_ADD_FLAGS(&loop->std, IS_OBJ_DESTRUCTOR_CALLED);
#endif
		destruct_uv_loop(&loop->std);
	}
}
/* }}} */

/* {{{ proto long uv_now([UVLoop $uv_loop = uv_default_loop()])
*/
PHP_FUNCTION(uv_now)
{
	php_uv_loop_t *loop = NULL;
	int64_t now;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		UV_PARAM_OBJ_NULL(loop, php_uv_loop_t, uv_loop_ce)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	now = uv_now(&loop->loop);
	RETURN_LONG((long)now);
}
/* }}} */


/* {{{ proto void uv_tcp_bind(UVTcp $uv_tcp, UVSockAddr $uv_sockaddr)
*/
PHP_FUNCTION(uv_tcp_bind)
{
	php_uv_socket_bind(PHP_UV_TCP_IPV4, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_tcp_bind6(UVTcp $uv_tcp, UVSockAddr $uv_sockaddr)
*/
PHP_FUNCTION(uv_tcp_bind6)
{
	php_uv_socket_bind(PHP_UV_TCP_IPV6, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */


/* {{{ proto void uv_write(UVStream $handle, string $data[, callable(UVStream $handle, long $status) $callback = function() {}])
*/
PHP_FUNCTION(uv_write)
{
	zend_string *data;
	int r;
	php_uv_t *uv;
	write_req_t *w;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(2, 3)
		UV_PARAM_OBJ(uv, php_uv_t, uv_stream_ce)
		Z_PARAM_STR(data)
		Z_PARAM_OPTIONAL
		Z_PARAM_FUNC_EX(fci, fcc, 1, 0)
	ZEND_PARSE_PARAMETERS_END();

	cb = php_uv_cb_init_dynamic(uv, &fci, &fcc);
	PHP_UV_INIT_WRITE_REQ(w, uv, data->val, data->len, cb)

	r = uv_write(&w->req, &uv->uv.stream, &w->buf, 1, php_uv_write_cb);
	if (r) {
		php_uv_free_write_req(w);
		php_error_docref(NULL, E_WARNING, "write failed");
	} else {
		GC_ADDREF(&uv->std);
		PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_write, uv);
	}
}
/* }}} */

/* {{{ proto void uv_write2(UvStream $handle, string $data, UVTcp|UvPipe $send, callable(UVStream $handle, long $status) $callback)
*/
PHP_FUNCTION(uv_write2)
{
	zend_string *data;
	int r;
	php_uv_t *uv, *send;
	write_req_t *w;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(4, 4)
		UV_PARAM_OBJ(uv, php_uv_t, uv_stream_ce)
		Z_PARAM_STR(data)
		UV_PARAM_OBJ(send, php_uv_t, uv_tcp_ce, uv_pipe_ce)
		Z_PARAM_FUNC(fci, fcc)
	ZEND_PARSE_PARAMETERS_END();

	cb = php_uv_cb_init_dynamic(uv, &fci, &fcc);
	PHP_UV_INIT_WRITE_REQ(w, uv, data->val, data->len, cb);

	r = uv_write2(&w->req, &uv->uv.stream, &w->buf, 1, &send->uv.stream, php_uv_write_cb);
	if (r) {
		php_uv_free_write_req(w);
		php_error_docref(NULL, E_ERROR, "write2 failed");
	} else {
		GC_ADDREF(&uv->std);
		PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_write2, uv);
	}
}
/* }}} */

/* {{{ proto void uv_tcp_nodelay(UVTcp $handle, bool $enable)
*/
PHP_FUNCTION(uv_tcp_nodelay)
{
	php_uv_t *client;
	zend_bool bval = 1;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(client, php_uv_t, uv_tcp_ce)
		Z_PARAM_BOOL(bval)
	ZEND_PARSE_PARAMETERS_END();

	uv_tcp_nodelay(&client->uv.tcp, bval);
}
/* }}} */

/* {{{ proto void uv_accept<T = UVTcp|UVPipe>(T $server, T $client)
*/
PHP_FUNCTION(uv_accept)
{
	php_uv_t *server, *client;
	int r;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(server, php_uv_t, uv_tcp_ce, uv_pipe_ce)
		UV_PARAM_OBJ(client, php_uv_t, uv_tcp_ce, uv_pipe_ce)
	ZEND_PARSE_PARAMETERS_END();

	if (server->std.ce != client->std.ce) {
		php_error_docref(NULL, E_WARNING, ".");
		zend_internal_type_error(ZEND_ARG_USES_STRICT_TYPES(), "%s expects server and client parameters to be either both of type UVTcp or both of type UVPipe", get_active_function_name());
		return;
	}

	r = uv_accept(&server->uv.stream, &client->uv.stream);
	if (r) {
		php_error_docref(NULL, E_WARNING, "%s", php_uv_strerror(r));
		RETURN_FALSE;
	}
}
/* }}} */


/* {{{ proto void uv_shutdown(UVStream $handle, callable(UVStream $handle, long $status) $callback)
*/
PHP_FUNCTION(uv_shutdown)
{
	php_uv_t *uv;
	uv_shutdown_t *shutdown;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;
	int r = 0;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_stream_ce)
		Z_PARAM_OPTIONAL
		Z_PARAM_FUNC_EX(fci, fcc, 1, 0)
	ZEND_PARSE_PARAMETERS_END();

	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_SHUTDOWN_CB);

	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_shutdown, uv);
	shutdown = emalloc(sizeof(uv_shutdown_t));
	shutdown->data = uv;

	r = uv_shutdown(shutdown, &uv->uv.stream, (uv_shutdown_cb)php_uv_shutdown_cb);
	if (r) {
		php_error_docref(NULL, E_WARNING, "%s", php_uv_strerror(r));
		efree(&shutdown);
	}

}
/* }}} */

/* {{{ proto void uv_close(UV $handle, callable(UV $handle) $callback)
*/
PHP_FUNCTION(uv_close)
{
	php_uv_t *uv;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_ce)
		Z_PARAM_OPTIONAL
		Z_PARAM_FUNC_EX(fci, fcc, 1, 0)
	ZEND_PARSE_PARAMETERS_END();

	if (!php_uv_closeable_type(uv)) {
		php_error_docref(NULL, E_WARNING, "passed UV handle (%s) is not closeable", ZSTR_VAL(uv->std.ce->name));
		RETURN_FALSE;
	}

	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_CLOSE_CB);

	php_uv_close(uv);
}
/* }}} */

/* {{{ proto void uv_read_start(UVStream $handle, callable(UVStream $handle, string|long $read) $callback)
*/
PHP_FUNCTION(uv_read_start)
{
	php_uv_t *uv;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;
	int r;
	uv_os_fd_t fd;

	PHP_UV_DEBUG_PRINT("uv_read_start\n");

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_stream_ce)
		Z_PARAM_FUNC(fci, fcc)
	ZEND_PARSE_PARAMETERS_END();

	if (uv_fileno(&uv->uv.handle, &fd) != 0) {
		php_error_docref(NULL, E_WARNING, "passed UV handle is not initialized yet");
		return;
	}

	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_read_start, uv);

	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_READ_CB);

	r = uv_read_start(&uv->uv.stream, php_uv_read_alloc, php_uv_read_cb);
	if (r) {
		php_error_docref(NULL, E_NOTICE, "read failed");
		OBJ_RELEASE(&uv->std);
	}
}
/* }}} */

/* {{{ proto void uv_read_stop(UVStream $handle)
*/
PHP_FUNCTION(uv_read_stop)
{
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_stream_ce)
	ZEND_PARSE_PARAMETERS_END();

	if (!uv_is_active(&uv->uv.handle)) {
		return;
	}

	uv_read_stop(&uv->uv.stream);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_read_stop, uv);
	OBJ_RELEASE(&uv->std);
}
/* }}} */

/* {{{ proto UVSockAddrIPv4 uv_ip4_addr(string $ipv4_addr, long $port)
*/
PHP_FUNCTION(uv_ip4_addr)
{
	zend_string *address;
	zend_long port = 0;
	php_uv_sockaddr_t *sockaddr;

	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"Sl", &address, &port) == FAILURE) {
		return;
	}

	PHP_UV_SOCKADDR_IPV4_INIT(sockaddr);
	uv_ip4_addr(address->val, port, &PHP_UV_SOCKADDR_IPV4(sockaddr));

	RETURN_OBJ(&sockaddr->std);
}
/* }}} */

/* {{{ proto UVSockAddrIPv6 uv_ip6_addr(string $ipv6_addr, long $port)
*/
PHP_FUNCTION(uv_ip6_addr)
{
	zend_string *address;
	zend_long port = 0;
	php_uv_sockaddr_t *sockaddr;

	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"Sl", &address, &port) == FAILURE) {
		return;
	}

	PHP_UV_SOCKADDR_IPV6_INIT(sockaddr);
	uv_ip6_addr(address->val, port, &PHP_UV_SOCKADDR_IPV6(sockaddr));

	RETURN_OBJ(&sockaddr->std);
}
/* }}} */


/* {{{ proto void uv_listen<T = UVTcp|UVPipe>(T $handle, long $backlog, callable(T $handle, long $status) $callback)
*/
PHP_FUNCTION(uv_listen)
{
	zend_long backlog = SOMAXCONN;
	php_uv_t *uv;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;
	int r;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		UV_PARAM_OBJ(uv, php_uv_t, uv_tcp_ce, uv_pipe_ce)
		Z_PARAM_LONG(backlog)
		Z_PARAM_FUNC(fci, fcc)
	ZEND_PARSE_PARAMETERS_END();

	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_listen, uv);
	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_LISTEN_CB);

	r = uv_listen(&uv->uv.stream, backlog, php_uv_listen_cb);
	if (r) {
		php_error_docref(NULL, E_WARNING, "%s", php_uv_strerror(r));
		OBJ_RELEASE(&uv->std);
	}
}
/* }}} */

/* {{{ proto void uv_tcp_connect(UVTcp $handle, UVSockAddr $sock_addr, callable(UVTcp $handle, long $status) $callback)
*/
PHP_FUNCTION(uv_tcp_connect)
{
	php_uv_tcp_connect(PHP_UV_TCP_IPV4, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */


/* {{{ proto void uv_tcp_connect6(UVTcp $handle, UVSockAddrIPv6 $ipv6_addr, callable(UVTcp $handle, long $status) $callback)
*/
PHP_FUNCTION(uv_tcp_connect6)
{
	php_error_docref(NULL, E_DEPRECATED, "uv_udp_send6: Use uv_udp_send() instead");
	php_uv_tcp_connect(PHP_UV_TCP_IPV6, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */


/* {{{ proto UVTimer uv_timer_init([UVLoop $loop = uv_default_loop()])
*/
PHP_FUNCTION(uv_timer_init)
{
	php_uv_loop_t *loop = NULL;
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		UV_PARAM_OBJ_NULL(loop, php_uv_loop_t, uv_loop_ce)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	PHP_UV_INIT_UV_EX(uv, uv_timer_ce, uv_timer_init);

	PHP_UV_DEBUG_PRINT("uv_timer_init: resource: %p\n", uv);

	RETURN_OBJ(&uv->std);
}
/* }}} */

/* {{{ proto void uv_timer_start(UVTimer $timer, long $timeout, long $repeat[, callable(UVTimer $timer) $callback = function() {}])
*/
PHP_FUNCTION(uv_timer_start)
{
	php_uv_t *uv;
	zend_long timeout, repeat = 0;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(3, 4)
		UV_PARAM_OBJ(uv, php_uv_t, uv_timer_ce)
		Z_PARAM_LONG(timeout)
		Z_PARAM_LONG(repeat)
		Z_PARAM_OPTIONAL
		Z_PARAM_FUNC_EX(fci, fcc, 1, 0)
	ZEND_PARSE_PARAMETERS_END();

	if (timeout < 0) {
		php_error_docref(NULL, E_WARNING, "timeout value have to be larger than 0. given %lld", timeout);
		RETURN_FALSE;
	}

	if (repeat < 0) {
		php_error_docref(NULL, E_WARNING, "repeat value have to be larger than 0. given %lld", repeat);
		RETURN_FALSE;
	}

	if (uv_is_active(&uv->uv.handle)) {
		php_error_docref(NULL, E_NOTICE, "Passed uv timer resource has been started. You don't have to call this method");
		RETURN_FALSE;
	}

	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_timer_start, uv);
	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_TIMER_CB);

	uv_timer_start((uv_timer_t*)&uv->uv.timer, php_uv_timer_cb, timeout, repeat);
}
/* }}} */

/* {{{ proto void uv_timer_stop(UVTimer $timer)
*/
PHP_FUNCTION(uv_timer_stop)
{
	php_uv_t *uv;
	int r = 0;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_timer_ce)
	ZEND_PARSE_PARAMETERS_END();

	if (!uv_is_active(&uv->uv.handle)) {
		php_error_docref(NULL, E_NOTICE, "Passed uv timer resource has been stopped. You don't have to call this method");
		RETURN_FALSE;
	}

	PHP_UV_DEBUG_PRINT("uv_timer_stop: resource: %p\n", uv);
	r = uv_timer_stop(&uv->uv.timer);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_timer_stop, uv);
	OBJ_RELEASE(&uv->std);

	RETURN_LONG(r);
}
/* }}} */

/* {{{ proto void uv_timer_again(UVTimer $timer)
*/
PHP_FUNCTION(uv_timer_again)
{
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_timer_ce)
	ZEND_PARSE_PARAMETERS_END();

	if (uv_is_active(&uv->uv.handle)) {
		php_error_docref(NULL, E_NOTICE, "Passed uv timer resource has been started. You don't have to call this method");
		RETURN_FALSE;
	}

	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_timer_again, uv);

	uv_timer_again(&uv->uv.timer);
}
/* }}} */

/* {{{ proto void uv_timer_set_repeat(UVTimer $timer, long $repeat)
*/
PHP_FUNCTION(uv_timer_set_repeat)
{
	php_uv_t *uv;
	zend_long repeat;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_timer_ce)
		Z_PARAM_LONG(repeat)
	ZEND_PARSE_PARAMETERS_END();

	uv_timer_set_repeat(&uv->uv.timer, repeat);
}
/* }}} */

/* {{{ proto long uv_timer_get_repeat(UVTimer $timer)
*/
PHP_FUNCTION(uv_timer_get_repeat)
{
	php_uv_t *uv;
	int64_t repeat;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_timer_ce)
	ZEND_PARSE_PARAMETERS_END();

	repeat = uv_timer_get_repeat(&uv->uv.timer);
	RETURN_LONG(repeat);
}
/* }}} */


/* {{{ proto UVIdle uv_idle_init([UVLoop $loop = uv_default_loop()])
*/
PHP_FUNCTION(uv_idle_init)
{
	php_uv_loop_t *loop = NULL;
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		UV_PARAM_OBJ_NULL(loop, php_uv_loop_t, uv_loop_ce)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	PHP_UV_INIT_UV_EX(uv, uv_idle_ce, uv_idle_init);

	RETURN_OBJ(&uv->std);
}
/* }}} */

/* {{{ proto void uv_idle_start(UVIdle $idle, callable $callback)
*/
PHP_FUNCTION(uv_idle_start)
{
	php_uv_t *uv;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;
	int r = 0;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_idle_ce)
		Z_PARAM_FUNC(fci, fcc)
	ZEND_PARSE_PARAMETERS_END();

	if (uv_is_active(&uv->uv.handle)) {
		php_error_docref(NULL, E_WARNING, "passed uv_idle resource has already started.");
		RETURN_FALSE;
	}

	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_idle_start, uv);

	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_IDLE_CB);

	r = uv_idle_start(&uv->uv.idle, (uv_idle_cb) php_uv_idle_cb);

	RETURN_LONG(r);
}
/* }}} */


/* {{{ proto void uv_idle_stop(UVIdle $idle)
*/
PHP_FUNCTION(uv_idle_stop)
{
	php_uv_t *uv;
	int r = 0;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_idle_ce)
	ZEND_PARSE_PARAMETERS_END();

	if (!uv_is_active(&uv->uv.handle)) {
		php_error_docref(NULL, E_NOTICE, "passed uv_idle resource does not start yet.");
		RETURN_FALSE;
	}

	r = uv_idle_stop(&uv->uv.idle);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_idle_stop, uv);
	OBJ_RELEASE(&uv->std);

	RETURN_LONG(r);
}
/* }}} */


/* {{{ proto void uv_getaddrinfo(UVLoop $loop, callable(array|long $addresses_or_error) $callback, string $node, string $service[, array $hints = []])
*/
PHP_FUNCTION(uv_getaddrinfo)
{
	zval *hints = NULL;
	php_uv_loop_t *loop;
	php_uv_t *uv = NULL;
	struct addrinfo hint = {0};
	zend_string *node, *service;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(4, 5)
		UV_PARAM_OBJ(loop, php_uv_loop_t, uv_loop_ce)
		Z_PARAM_FUNC(fci, fcc)
		Z_PARAM_STR(node)
		Z_PARAM_STR(service)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY(hints)
	ZEND_PARSE_PARAMETERS_END();

	if (hints != NULL) {
		HashTable *h;
		zval *data;

		h = Z_ARRVAL_P(hints);
		if ((data = zend_hash_str_find(h, ZEND_STRL("ai_family")))) {
			hint.ai_family = Z_LVAL_P(data);
		}
		if ((data = zend_hash_str_find(h, ZEND_STRL("ai_socktype")))) {
			hint.ai_socktype = Z_LVAL_P(data);
		}
		if ((data = zend_hash_str_find(h, ZEND_STRL("ai_protocol")))) {
			hint.ai_socktype = Z_LVAL_P(data);
		}
		if ((data = zend_hash_str_find(h, ZEND_STRL("ai_flags")))) {
			hint.ai_flags = Z_LVAL_P(data);
		}
	}

	PHP_UV_INIT_UV(uv, uv_addrinfo_ce);

	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_GETADDR_CB);
	uv_getaddrinfo(&loop->loop, &uv->uv.addrinfo, php_uv_getaddrinfo_cb, node->val, service->val, &hint);
}
/* }}} */

/* {{{ proto UVTcp uv_tcp_init([UVLoop $loop])
*/
PHP_FUNCTION(uv_tcp_init)
{
	php_uv_loop_t *loop = NULL;
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		UV_PARAM_OBJ_NULL(loop, php_uv_loop_t, uv_loop_ce)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	PHP_UV_INIT_UV_EX(uv, uv_tcp_ce, uv_tcp_init);

	RETURN_OBJ(&uv->std);
}
/* }}} */

/* {{{ proto int|false uv_tcp_open(UVTcp $handle, long|resource $tcpfd)
*/
PHP_FUNCTION(uv_tcp_open)
{
	php_uv_handle_open((int (*)(uv_handle_t *, long)) uv_tcp_open, uv_tcp_ce, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto UVLoop uv_default_loop()
*/
PHP_FUNCTION(uv_default_loop)
{
	php_uv_loop_t *loop = php_uv_default_loop();
	GC_ADDREF(&loop->std);
	RETURN_OBJ(&loop->std);
}
/* }}} */

/* {{{ proto UVLoop uv_loop_new()
*/
PHP_FUNCTION(uv_loop_new)
{
	object_init_ex(return_value, uv_loop_ce);
}
/* }}} */


/* {{{ proto UVUdp uv_udp_init([UVLoop $loop])
*/
PHP_FUNCTION(uv_udp_init)
{
	php_uv_loop_t *loop = NULL;
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		UV_PARAM_OBJ_NULL(loop, php_uv_loop_t, uv_loop_ce)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	PHP_UV_INIT_UV_EX(uv, uv_udp_ce, uv_udp_init);

	RETURN_OBJ(&uv->std);
}
/* }}} */

/* {{{ proto int|false uv_udp_open(UVUdp $handle, long|resource $udpfd)
*/
PHP_FUNCTION(uv_udp_open)
{
	php_uv_handle_open((int (*)(uv_handle_t *, long)) uv_udp_open, uv_udp_ce, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_udp_bind(UVUdp $resource, UVSockAddr $address[, long $flags = 0])
*/
PHP_FUNCTION(uv_udp_bind)
{
	php_uv_socket_bind(PHP_UV_UDP_IPV4, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_udp_bind6(UVUdp $resource, UVSockAddr $address[, long $flags = 0])
*/
PHP_FUNCTION(uv_udp_bind6)
{
	php_uv_socket_bind(PHP_UV_UDP_IPV6, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_udp_recv_start(UVUdp $handle, callable(UVUdp $handle, string|long $read, long $flags) $callback)
*/
PHP_FUNCTION(uv_udp_recv_start)
{
	php_uv_t *uv;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;
	int r;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_udp_ce)
		Z_PARAM_FUNC(fci, fcc)
	ZEND_PARSE_PARAMETERS_END();

	if (uv_is_active(&uv->uv.handle)) {
		php_error_docref(NULL, E_WARNING, "passed uv_resource has already activated.");
		RETURN_FALSE;
	}

	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_udp_recv_start, uv);

	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_RECV_CB);
	r = uv_udp_recv_start(&uv->uv.udp, php_uv_read_alloc, php_uv_udp_recv_cb);
	if (r) {
		php_error_docref(NULL, E_NOTICE, "read failed");
		OBJ_RELEASE(&uv->std);
	}
}
/* }}} */

/* {{{ proto void uv_udp_recv_stop(UVUdp $handle)
*/
PHP_FUNCTION(uv_udp_recv_stop)
{
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_udp_ce)
	ZEND_PARSE_PARAMETERS_END();

	if (!uv_is_active(&uv->uv.handle)) {
		php_error_docref(NULL, E_NOTICE, "passed uv_resource has already stopped.");
		RETURN_FALSE;
	}

	uv_udp_recv_stop(&uv->uv.udp);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_udp_recv_stop, uv);
	OBJ_RELEASE(&uv->std);
}
/* }}} */

/* {{{ proto long uv_udp_set_membership(UVUdp $handle, string $multicast_addr, string $interface_addr, long $membership)
*/
PHP_FUNCTION(uv_udp_set_membership)
{
	php_uv_t *uv;
	zend_string *multicast_addr, *interface_addr;
	int error;
	zend_long membership;

	ZEND_PARSE_PARAMETERS_START(4, 4)
		UV_PARAM_OBJ(uv, php_uv_t, uv_udp_ce)
		Z_PARAM_STR(multicast_addr)
		Z_PARAM_STR(interface_addr)
		Z_PARAM_LONG(membership)
	ZEND_PARSE_PARAMETERS_END();

	error = uv_udp_set_membership(&uv->uv.udp, (const char *) multicast_addr->val, (const char *) interface_addr->val, membership);

	RETURN_LONG(error);
}
/* }}} */


/* {{{ proto void uv_udp_set_multicast_loop(UVUdp $handle, bool $enabled)
*/
PHP_FUNCTION(uv_udp_set_multicast_loop)
{
	php_uv_t *uv;
	zend_bool enabled = 0;
	int r;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_udp_ce)
		Z_PARAM_BOOL(enabled)
	ZEND_PARSE_PARAMETERS_END();

	r = uv_udp_set_multicast_loop((uv_udp_t*)&uv->uv.udp, enabled);
	if (r) {
		php_error_docref(NULL, E_NOTICE, "uv_udp_set_muticast_loop failed");
	}
}
/* }}} */

/* {{{ proto void uv_udp_set_multicast_ttl(UVUdp $handle, long $ttl)
*/
PHP_FUNCTION(uv_udp_set_multicast_ttl)
{
	php_uv_t *uv;
	zend_long ttl = 0; /* 1 through 255 */
	int r;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_udp_ce)
		Z_PARAM_LONG(ttl)
	ZEND_PARSE_PARAMETERS_END();

	if (ttl > 255) {
		php_error_docref(NULL, E_NOTICE, "uv_udp_set_muticast_ttl: ttl parameter expected smaller than 255.");
		ttl = 255;
	} else if (ttl < 1) {
		php_error_docref(NULL, E_NOTICE, "uv_udp_set_muticast_ttl: ttl parameter expected larger than 0.");
		ttl = 1;
	}

	r = uv_udp_set_multicast_ttl(&uv->uv.udp, ttl);
	if (r) {
		php_error_docref(NULL, E_NOTICE, "uv_udp_set_muticast_ttl failed");
	}
}
/* }}} */

/* {{{ proto void uv_udp_set_broadcast(UVUdp $handle, bool $enabled)
*/
PHP_FUNCTION(uv_udp_set_broadcast)
{
	php_uv_t *uv;
	zend_bool enabled = 0;
	int r;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_udp_ce)
		Z_PARAM_BOOL(enabled)
	ZEND_PARSE_PARAMETERS_END();

	r = uv_udp_set_broadcast(&uv->uv.udp, enabled);
	if (r) {
		php_error_docref(NULL, E_NOTICE, "uv_udp_set_muticast_loop failed");
	}
}
/* }}} */

/* {{{ proto void uv_udp_send(UVUdp $handle, string $data, UVSockAddr $uv_addr, callable(UVUdp $handle, long $status) $callback)
*/
PHP_FUNCTION(uv_udp_send)
{
	php_uv_udp_send(1, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_udp_send6(resource $handle, string $data, UVSockAddrIPv6 $uv_addr6, callable(UVUdp $handle, long $status) $callback)
*/
PHP_FUNCTION(uv_udp_send6)
{
	php_error_docref(NULL, E_DEPRECATED, "uv_udp_send6: Use uv_udp_send() instead");
	php_uv_udp_send(2, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto bool uv_is_active(UV $handle)
*/
PHP_FUNCTION(uv_is_active)
{
	zval *zv;
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_OBJECT_OF_CLASS(zv, uv_ce)
	ZEND_PARSE_PARAMETERS_END();

	uv = (php_uv_t *) Z_OBJ_P(zv);

	RETURN_BOOL(!PHP_UV_IS_DTORED(uv) && uv_is_active(&uv->uv.handle));
}
/* }}} */

/* {{{ proto bool uv_is_closing(UV $handle)
*/
PHP_FUNCTION(uv_is_closing)
{
	zval *zv;
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_OBJECT_OF_CLASS(zv, uv_ce)
	ZEND_PARSE_PARAMETERS_END();

	uv = (php_uv_t *) Z_OBJ_P(zv);

	RETURN_BOOL(PHP_UV_IS_DTORED(uv));
}
/* }}} */

/* {{{ proto bool uv_is_readable(UVStream $handle)
*/
PHP_FUNCTION(uv_is_readable)
{
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_stream_ce)
	ZEND_PARSE_PARAMETERS_END();

	RETURN_BOOL(uv_is_readable(&uv->uv.stream));
}
/* }}} */

/* {{{ proto bool uv_is_writable(UVStream $handle)
*/
PHP_FUNCTION(uv_is_writable)
{
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_stream_ce)
	ZEND_PARSE_PARAMETERS_END();

	RETURN_BOOL(uv_is_writable(&uv->uv.stream));
}
/* }}} */


/* {{{ proto bool uv_walk(UVLoop $loop, callable $closure[, array $opaque])
*/
PHP_FUNCTION(uv_walk)
{
	zval *opaque = NULL;
	php_uv_loop_t *loop;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	//php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(2, 3)
		UV_PARAM_OBJ(loop, php_uv_loop_t, uv_loop_ce)
		Z_PARAM_FUNC(fci, fcc)
		Z_PARAM_OPTIONAL
		Z_PARAM_ARRAY(opaque)
	ZEND_PARSE_PARAMETERS_END();

	php_error_docref(NULL, E_ERROR, "uv_walk not yet supported");

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	uv_walk(&loop->loop, php_uv_walk_cb, NULL);
}
/* }}} */

/* {{{ proto long uv_guess_handle(resource $uv)
*/
PHP_FUNCTION(uv_guess_handle)
{
	zval *handle;
	long fd = -1;
	uv_handle_type type;

	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"r", &handle) == FAILURE) {
		return;
	}

	fd = php_uv_zval_to_fd(handle);
	if (fd < 0) {
		php_error_docref(NULL, E_WARNING, "invalid variable passed. can't convert to fd.");
		return;
	}
	type = uv_guess_handle(fd);

	RETURN_LONG(type);
}
/* }}} */


/* {{{ proto UVPipe uv_pipe_init([UVLoop $loop = uv_default_loop(), bool $ipc = false])
*/
PHP_FUNCTION(uv_pipe_init)
{
	php_uv_t *uv;
	php_uv_loop_t *loop = NULL;
	zend_bool ipc = 0;

	ZEND_PARSE_PARAMETERS_START(0, 2)
		Z_PARAM_OPTIONAL
		UV_PARAM_OBJ_NULL(loop, php_uv_loop_t, uv_loop_ce)
		Z_PARAM_BOOL(ipc)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);

	PHP_UV_INIT_UV_EX(uv, uv_pipe_ce, uv_pipe_init, (int) ipc);

	RETURN_OBJ(&uv->std);
}
/* }}} */

/* {{{ proto long|false uv_pipe_open(UVPipe $handle, resource|long $pipe)
*/
PHP_FUNCTION(uv_pipe_open)
{
	php_uv_handle_open((int (*)(uv_handle_t *, long)) uv_pipe_open, uv_pipe_ce, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto long uv_pipe_bind(UVPipe $handle, string $name)
*/
PHP_FUNCTION(uv_pipe_bind)
{
	php_uv_t *uv;
	zend_string *name;
	int error;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_pipe_ce)
		Z_PARAM_STR(name)
	ZEND_PARSE_PARAMETERS_END();

	error = uv_pipe_bind(&uv->uv.pipe, name->val);
	if (error) {
		php_error_docref(NULL, E_WARNING, "%s", php_uv_strerror(error));
	}

	RETURN_LONG(error);
}
/* }}} */

/* {{{ proto void uv_pipe_connect(UVPipe $handle, string $path, callable(UVPipe $handle, long $status) $callback)
*/
PHP_FUNCTION(uv_pipe_connect)
{
	php_uv_t *uv;
	zend_string *name;
	uv_connect_t *req;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		UV_PARAM_OBJ(uv, php_uv_t, uv_pipe_ce)
		Z_PARAM_STR(name)
		Z_PARAM_FUNC(fci, fcc)
	ZEND_PARSE_PARAMETERS_END();

	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_pipe_connect, uv);

	req = (uv_connect_t *) emalloc(sizeof(uv_connect_t));
	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_PIPE_CONNECT_CB);

	req->data = uv;
	uv_pipe_connect(req, &uv->uv.pipe, name->val, php_uv_pipe_connect_cb);
}
/* }}} */

/* {{{ proto void uv_pipe_pending_instances(UVPipe $handle, long $count)
*/
PHP_FUNCTION(uv_pipe_pending_instances)
{
	php_uv_t *uv;
	zend_long count;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_pipe_ce)
		Z_PARAM_LONG(count)
	ZEND_PARSE_PARAMETERS_END();

	uv_pipe_pending_instances(&uv->uv.pipe, count);
}
/* }}} */

/* {{{ proto void uv_pipe_pending_count(UVPipe $handle)
*/
PHP_FUNCTION(uv_pipe_pending_count)
{
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_pipe_ce)
	ZEND_PARSE_PARAMETERS_END();

	RETURN_LONG(uv_pipe_pending_count(&uv->uv.pipe));
}
/* }}} */

/* {{{ proto void uv_pipe_pending_type(UVPipe $handle)
*/
PHP_FUNCTION(uv_pipe_pending_type)
{
	php_uv_t *uv;
	uv_handle_type ret;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_pipe_ce)
	ZEND_PARSE_PARAMETERS_END();

	ret = uv_pipe_pending_type(&uv->uv.pipe);
	RETURN_LONG(ret);
}
/* }}} */

/* {{{ proto UVStdio uv_stdio_new([UV|resource|long|null $fd[, long $flags = 0]])
*/
PHP_FUNCTION(uv_stdio_new)
{
	php_uv_stdio_t *stdio;
	zval *handle;
	zend_long flags = 0;
#if !defined(PHP_WIN32) || defined(HAVE_SOCKET)
	php_socket *socket;
#endif
	php_socket_t fd = -1;
	php_stream *stream;

	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"|zl", &handle, &flags) == FAILURE) {
		return;
	}

	if (handle == NULL || Z_TYPE_P(handle) == IS_NULL) {
		flags = UV_IGNORE;
	} else if (Z_TYPE_P(handle) == IS_LONG) {
		fd = Z_LVAL_P(handle);
		if (flags & (UV_CREATE_PIPE | UV_INHERIT_STREAM)) {
			php_error_docref(NULL, E_WARNING, "flags must not be UV::CREATE_PIPE or UV::INHERIT_STREAM for resources");
			RETURN_FALSE;
		}
		flags |= UV_INHERIT_FD;
	} else if (Z_TYPE_P(handle) == IS_RESOURCE) {
		if ((stream = (php_stream *) zend_fetch_resource_ex(handle, NULL, php_file_le_stream()))) {
			if (php_stream_cast(stream, PHP_STREAM_AS_FD | PHP_STREAM_CAST_INTERNAL, (void *) &fd, 1) != SUCCESS || fd < 0) {
				php_error_docref(NULL, E_WARNING, "passed resource without file descriptor");
				RETURN_FALSE;
			}
#if PHP_VERSION_ID < 80000 && (!defined(PHP_WIN32) || (defined(HAVE_SOCKET) && !defined(COMPILE_DL_SOCKETS)))
		} else if ((socket = (php_socket *) zend_fetch_resource_ex(handle, NULL, php_sockets_le_socket()))) {
			fd = socket->bsd_socket;
#endif
		} else {
			php_error_docref(NULL, E_WARNING, "passed unexpected resource, expected file or socket");
			RETURN_FALSE;
		}
		if (flags & (UV_CREATE_PIPE | UV_INHERIT_STREAM)) {
			php_error_docref(NULL, E_WARNING, "flags must not be UV::CREATE_PIPE or UV::INHERIT_STREAM for resources");
			RETURN_FALSE;
		}
		flags |= UV_INHERIT_FD;
	} else if (Z_TYPE_P(handle) == IS_OBJECT && instanceof_function(Z_OBJCE_P(handle), uv_ce)) {
		if (flags & UV_INHERIT_FD) {
			php_error_docref(NULL, E_WARNING, "flags must not be UV::INHERIT_FD for UV handles");
			RETURN_FALSE;
		}
		if ((flags & (UV_CREATE_PIPE | UV_INHERIT_STREAM)) == (UV_CREATE_PIPE | UV_INHERIT_STREAM) || !(flags & (UV_CREATE_PIPE | UV_INHERIT_STREAM))) {
			php_error_docref(NULL, E_WARNING, "flags must be exactly one of UV::INHERIT_STREAM or UV::CREATE_PIPE for UV handles");
			RETURN_FALSE;
		}
#if PHP_VERSION_ID >= 80000 && (!defined(PHP_WIN32) || (defined(HAVE_SOCKETS) && !defined(COMPILE_DL_SOCKETS)))
	} else if (socket_ce && Z_TYPE_P(handle) == IS_OBJECT && Z_OBJCE_P(handle) == socket_ce && (socket = (php_socket *) ((char *)(Z_OBJ_P(handle)) - XtOffsetOf(php_socket, std)))) {
		fd = socket->bsd_socket;
		if (flags & (UV_CREATE_PIPE | UV_INHERIT_STREAM)) {
			php_error_docref(NULL, E_WARNING, "flags must not be UV::CREATE_PIPE or UV::INHERIT_STREAM for socket objects");
			RETURN_FALSE;
		}
		flags |= UV_INHERIT_FD;
#endif
	} else {
		php_error_docref(NULL, E_WARNING, "passed unexpected value, expected instance of UV, file resource or socket object");
		RETURN_FALSE;
	}

	PHP_UV_INIT_GENERIC(stdio, php_uv_stdio_t, uv_stdio_ce);
	stdio->flags = flags;
	stdio->fd = fd;

	if (Z_TYPE_P(handle) == IS_RESOURCE || Z_TYPE_P(handle) == IS_OBJECT) {
		ZVAL_COPY(&stdio->stream, handle);
	}

	RETURN_OBJ(&stdio->std);
}
/* }}} */


/* {{{ proto array uv_loadavg(void)
*/
PHP_FUNCTION(uv_loadavg)
{
	double average[3];

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	uv_loadavg(average);

	array_init(return_value);
	add_next_index_double(return_value, average[0]);
	add_next_index_double(return_value, average[1]);
	add_next_index_double(return_value, average[2]);
}
/* }}} */

/* {{{ proto double uv_uptime(void)
*/
PHP_FUNCTION(uv_uptime)
{
	double uptime;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	uv_uptime(&uptime);

	RETURN_DOUBLE(uptime);
}
/* }}} */

/* {{{ proto long uv_get_free_memory(void)
*/
PHP_FUNCTION(uv_get_free_memory)
{
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	RETURN_LONG(uv_get_free_memory());
}
/* }}} */

/* {{{ proto long uv_get_total_memory(void)
*/
PHP_FUNCTION(uv_get_total_memory)
{
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	RETURN_LONG(uv_get_total_memory());
}
/* }}} */

/* {{{ proto long uv_hrtime(void)
*/
PHP_FUNCTION(uv_hrtime)
{
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	RETURN_LONG(uv_hrtime());
}
/* }}} */

/* {{{ proto string uv_exepath(void)
*/
PHP_FUNCTION(uv_exepath)
{
	char buffer[MAXPATHLEN];
	size_t buffer_sz = sizeof(buffer) / sizeof(buffer[0]);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	if (uv_exepath(buffer, &buffer_sz) == UV_EINVAL) {
		RETURN_FALSE; /* should be unreeachable */
	}

	RETURN_STRINGL(buffer, buffer_sz);
}
/* }}} */

/* {{{ proto string uv_cwd(void)
*/
PHP_FUNCTION(uv_cwd)
{
	char buffer[MAXPATHLEN];
	size_t buffer_sz = sizeof(buffer) / sizeof(buffer[0]);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	uv_cwd(buffer, &buffer_sz);

	RETURN_STRING(buffer);
}
/* }}} */

/* {{{ proto array uv_cpu_info(void)
*/
PHP_FUNCTION(uv_cpu_info)
{
	uv_cpu_info_t *cpus;
	int error;
	int i, count;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	error = uv_cpu_info(&cpus, &count);
	if (0 == error) {
		array_init(return_value);

		for (i = 0; i < count; i++) {
			zval tmp, times;

			array_init(&tmp);
			array_init(&times);

			add_assoc_string_ex(&tmp, ZEND_STRL("model"), cpus[i].model);
			add_assoc_long_ex(&tmp,   ZEND_STRL("speed"), cpus[i].speed);

			add_assoc_long_ex(&times, ZEND_STRL("sys"),  (size_t)cpus[i].cpu_times.sys);
			add_assoc_long_ex(&times, ZEND_STRL("user"), (size_t)cpus[i].cpu_times.user);
			add_assoc_long_ex(&times, ZEND_STRL("idle"), (size_t)cpus[i].cpu_times.idle);
			add_assoc_long_ex(&times, ZEND_STRL("irq"),  (size_t)cpus[i].cpu_times.irq);
			add_assoc_long_ex(&times, ZEND_STRL("nice"), (size_t)cpus[i].cpu_times.nice);
			add_assoc_zval_ex(&tmp,   ZEND_STRL("times"), &times);

			add_next_index_zval(return_value, &tmp);
		}

		uv_free_cpu_info(cpus, count);
	}
}
/* }}} */


/* {{{ proto array uv_interface_addresses(void)
*/
PHP_FUNCTION(uv_interface_addresses)
{
	uv_interface_address_t *interfaces;
	int error;
	char buffer[512];
	int i, count;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	error = uv_interface_addresses(&interfaces, &count);
	if (0 == error) {
		array_init(return_value);

		for (i = 0; i < count; i++) {
			zval tmp;

			array_init(&tmp);

			add_assoc_string_ex(&tmp, ZEND_STRL("name"), interfaces[i].name);
			add_assoc_bool_ex(&tmp, ZEND_STRL("is_internal"), interfaces[i].is_internal);

			if (interfaces[i].address.address4.sin_family == AF_INET) {
				uv_ip4_name(&interfaces[i].address.address4, buffer, sizeof(buffer));
			} else if (interfaces[i].address.address4.sin_family == AF_INET6) {
				uv_ip6_name(&interfaces[i].address.address6, buffer, sizeof(buffer));
			}
			add_assoc_string_ex(&tmp, ZEND_STRL("address"), buffer);

			add_next_index_zval(return_value, &tmp);
		}
		uv_free_interface_addresses(interfaces, count);
	}
}
/* }}} */

/* {{{ proto UVProcess|long uv_spawn(UVLoop $loop, string $command, array $args, array $stdio, string $cwd, array $env, callable(UVProcess $process, long $exit_status, long $term_signal) $callback[, long $flags = 0, array $options = []])
*/
PHP_FUNCTION(uv_spawn)
{
	php_uv_loop_t *loop;
	uv_process_options_t options = {0};
	uv_stdio_container_t *stdio = NULL;
	php_uv_t *proc;
	zval *args, *env, *zoptions = NULL, *zstdio = NULL, *value;
	char **command_args, **zenv;
	zend_string *command, *cwd;
	int uid = 0, gid = 0, stdio_count = 0, ret;
	zend_long flags = 0;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(7, 9)
		UV_PARAM_OBJ(loop, php_uv_loop_t, uv_loop_ce)
		Z_PARAM_STR(command)
		Z_PARAM_ARRAY(args)
		Z_PARAM_ARRAY(zstdio)
		Z_PARAM_STR(cwd)
		Z_PARAM_ARRAY(env)
		Z_PARAM_FUNC(fci, fcc)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(flags)
		Z_PARAM_ARRAY(zoptions)
	ZEND_PARSE_PARAMETERS_END();

	memset(&options, 0, sizeof(uv_process_options_t));

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);

	{/* process stdio */
		HashTable *stdio_container;
		int x = 0;

		stdio_container = Z_ARRVAL_P(zstdio);
		stdio_count = zend_hash_num_elements(stdio_container);

		stdio = emalloc(sizeof(uv_stdio_container_t) * stdio_count);

		ZEND_HASH_FOREACH_VAL(stdio_container, value) {
			php_uv_stdio_t *stdio_tmp;

			if (Z_TYPE_P(value) != IS_OBJECT || Z_OBJCE_P(value) != uv_stdio_ce) {
				php_error_docref(NULL, E_ERROR, "must be instance of UVStdio");
			}

			stdio_tmp = (php_uv_stdio_t *) Z_OBJ_P(value);

			stdio[x].flags = stdio_tmp->flags;

			if (stdio_tmp->flags & UV_INHERIT_FD) {
				stdio[x].data.fd = stdio_tmp->fd;
			} else if (stdio_tmp->flags & (UV_CREATE_PIPE | UV_INHERIT_STREAM)) {
				php_uv_t *uv_pipe = (php_uv_t *) Z_OBJ(stdio_tmp->stream);
				stdio[x].data.stream = &uv_pipe->uv.stream;
			} else {
				php_error_docref(NULL, E_WARNING, "passes unexpected stdio flags");
				RETURN_FALSE;
			}

			x++;
		} ZEND_HASH_FOREACH_END();
	}

	{
		HashTable *h;
		zval *value;
		int n = 0;
		int hash_len = 0;

		h = Z_ARRVAL_P(args);

		hash_len = zend_hash_num_elements(h);

		command_args = ecalloc(hash_len+2, sizeof(char**));
		command_args[n] = command->val;

		n++;
		ZEND_HASH_FOREACH_VAL(h, value) {
			command_args[n] = Z_STRVAL_P(value);
			n++;
		} ZEND_HASH_FOREACH_END();

		command_args[n] = NULL;
	}

	{ /* env */
		HashTable *tmp_env;
		zend_string *key;
		int i = 0;
		zval *value;

		tmp_env = Z_ARRVAL_P(env);

		zenv = ecalloc(zend_hash_num_elements(tmp_env)+1, sizeof(char*));
		ZEND_HASH_FOREACH_STR_KEY_VAL(tmp_env, key, value) {
			char *tmp_env_entry;

			tmp_env_entry = emalloc(sizeof(char) * (key->len + 2 + Z_STRLEN_P(value)));
			slprintf(tmp_env_entry, key->len + 2 + Z_STRLEN_P(value), "%s=%s", key->val, Z_STRVAL_P(value));

			zenv[i++] = tmp_env_entry;
		} ZEND_HASH_FOREACH_END();
		zenv[i] = NULL;
	}

	if (zoptions != NULL && Z_TYPE_P(zoptions) != IS_NULL){
		HashTable *opts;
		zval *data;

		opts = Z_ARRVAL_P(zoptions);

		if ((data = zend_hash_str_find(opts, ZEND_STRL("uid")))) {
			uid = Z_LVAL_P(data);
		}

		if ((data = zend_hash_str_find(opts, ZEND_STRL("gid")))) {
			gid = Z_LVAL_P(data);
		}
	}

	options.file    = command->val;
	options.stdio   = stdio;
	options.exit_cb = php_uv_process_close_cb;
	options.env     = zenv;
	options.args    = command_args;
	options.cwd     = cwd->val;
	options.stdio   = stdio;
	options.stdio_count = stdio_count;
	options.flags = flags;
	options.uid = uid;
	options.gid = gid;

	PHP_UV_INIT_UV(proc, uv_process_ce);

	ret = uv_spawn(&loop->loop, &proc->uv.process, &options);

	if (ret) {
		OBJ_RELEASE(&proc->std);
		RETVAL_LONG(ret);
	} else {
		php_uv_cb_init(&cb, proc, &fci, &fcc, PHP_UV_PROC_CLOSE_CB);
		GC_ADDREF(&proc->std);
		PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_spawn, proc);
		RETVAL_OBJ(&proc->std);
	}

	if (zenv != NULL) {
		char **p = zenv;
		while(*p != NULL) {
			efree(*p);
			p++;
		}
		efree(zenv);
	}
	if (command_args != NULL) {
		efree(command_args);
	}

	if (stdio != NULL) {
		efree(stdio);
	}
}
/* }}} */


/* {{{ proto void uv_process_kill(UVProcess $handle, long $signal)
*/
PHP_FUNCTION(uv_process_kill)
{
	php_uv_t *uv;
	zend_long signal;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_process_ce)
		Z_PARAM_LONG(signal)
	ZEND_PARSE_PARAMETERS_END();

	uv_process_kill(&uv->uv.process, signal);
}
/* }}} */

/* {{{ proto void uv_process_get_pid(UVProcess $handle)
*/
PHP_FUNCTION(uv_process_get_pid)
{
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_process_ce)
	ZEND_PARSE_PARAMETERS_END();

	RETURN_LONG(uv_process_get_pid(&uv->uv.process));
}
/* }}} */

/* {{{ proto void uv_kill(long $pid, long $signal)
*/
PHP_FUNCTION(uv_kill)
{
	zend_long pid, signal;

	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"ll", &pid, &signal) == FAILURE) {
		return;
	}
	uv_kill(pid, signal);
}
/* }}} */

/* {{{ proto bool uv_chdir(string $directory)
*/
PHP_FUNCTION(uv_chdir)
{
	int error;
	zend_string *directory;

	if (zend_parse_parameters(ZEND_NUM_ARGS(),
		"S", &directory) == FAILURE) {
		return;
	}
	error = uv_chdir(directory->val);
	if (error == 0) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */


/* {{{ proto UVLock uv_rwlock_init(void)
*/
PHP_FUNCTION(uv_rwlock_init)
{
	php_uv_lock_init(IS_UV_RWLOCK, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto null|false uv_rwlock_rdlock(UVLock $handle)
*/
PHP_FUNCTION(uv_rwlock_rdlock)
{
	php_uv_lock_lock(IS_UV_RWLOCK_RD, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto bool uv_rwlock_tryrdlock(UVLock $handle)
*/
PHP_FUNCTION(uv_rwlock_tryrdlock)
{
	php_uv_lock_trylock(IS_UV_RWLOCK_RD, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_rwlock_rdunlock(UVLock $handle)
*/
PHP_FUNCTION(uv_rwlock_rdunlock)
{
	php_uv_lock_unlock(IS_UV_RWLOCK_RD, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto null|false uv_rwlock_wrlock(UVLock $handle)
*/
PHP_FUNCTION(uv_rwlock_wrlock)
{
	php_uv_lock_lock(IS_UV_RWLOCK_WR, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto bool uv_rwlock_trywrlock(UVLock $handle)
*/
PHP_FUNCTION(uv_rwlock_trywrlock)
{
	php_uv_lock_trylock(IS_UV_RWLOCK_WR, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_rwlock_wrunlock(UVLock $handle)
*/
PHP_FUNCTION(uv_rwlock_wrunlock)
{
	php_uv_lock_unlock(IS_UV_RWLOCK_WR, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto UVLock uv_mutex_init(void)
*/
PHP_FUNCTION(uv_mutex_init)
{
	php_uv_lock_init(IS_UV_MUTEX, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_mutex_lock(UVLock $lock)
*/
PHP_FUNCTION(uv_mutex_lock)
{
	php_uv_lock_lock(IS_UV_MUTEX, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto bool uv_mutex_trylock(UVLock $lock)
*/
PHP_FUNCTION(uv_mutex_trylock)
{
	php_uv_lock_trylock(IS_UV_MUTEX, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ void uv_mutex_unlock(UVLock $lock)

##### *Description*

unlock mutex

##### *Parameters*

*UVLock $lock*: uv resource handle (uv mutex)

##### *Return Value*

*void *:

##### *Example*

*/
PHP_FUNCTION(uv_mutex_unlock)
{
	php_uv_lock_unlock(IS_UV_MUTEX, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto UVLock uv_sem_init(long $value)
*/
PHP_FUNCTION(uv_sem_init)
{
	php_uv_lock_init(IS_UV_SEMAPHORE, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_sem_post(UVLock $sem)
*/
PHP_FUNCTION(uv_sem_post)
{
	php_uv_lock_lock(IS_UV_SEMAPHORE, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_sem_wait(UVLock $sem)
*/
PHP_FUNCTION(uv_sem_wait)
{
	php_uv_lock_unlock(IS_UV_SEMAPHORE, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto long uv_sem_trywait(UVLock $sem)
*/
PHP_FUNCTION(uv_sem_trywait)
{
	php_uv_lock_trylock(IS_UV_SEMAPHORE, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto UVPrepare uv_prepare_init(UVLoop $loop)
*/
PHP_FUNCTION(uv_prepare_init)
{
	php_uv_loop_t *loop = NULL;
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		UV_PARAM_OBJ_NULL(loop, php_uv_loop_t, uv_loop_ce)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	PHP_UV_INIT_UV_EX(uv, uv_prepare_ce, uv_prepare_init);

	RETURN_OBJ(&uv->std);
}
/* }}} */

/* {{{ proto long uv_prepare_start(UVPrepare $handle, callable(UVPrepare $handle) $callback)
*/
PHP_FUNCTION(uv_prepare_start)
{
	php_uv_t *uv;
	int r;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	PHP_UV_DEBUG_PRINT("uv_prepare_start\n");

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_prepare_ce)
		Z_PARAM_FUNC(fci, fcc)
	ZEND_PARSE_PARAMETERS_END();

	if (uv_is_active(&uv->uv.handle)) {
		php_error_docref(NULL, E_WARNING, "passed uv_prepare resource has been started.");
		RETURN_FALSE;
	}

	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_prepare_start, uv);

	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_PREPARE_CB);
	r = uv_prepare_start(&uv->uv.prepare, php_uv_prepare_cb);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_prepare_start, uv);

	RETURN_LONG(r);
}
/* }}} */

/* {{{ proto long uv_prepare_stop(UVPrepare $handle)
*/
PHP_FUNCTION(uv_prepare_stop)
{
	php_uv_t *uv;
	int r = 0;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_prepare_ce)
	ZEND_PARSE_PARAMETERS_END();

	if (!uv_is_active(&uv->uv.handle)) {
		php_error_docref(NULL, E_NOTICE, "passed uv_prepare resource has been stopped.");
		RETURN_FALSE;
	}

	r = uv_prepare_stop(&uv->uv.prepare);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_prepare_stop, uv);
	OBJ_RELEASE(&uv->std);

	RETURN_LONG(r);
}
/* }}} */

/* {{{ proto UVCheck uv_check_init([UVLoop $loop])
*/
PHP_FUNCTION(uv_check_init)
{
	php_uv_loop_t *loop = NULL;
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		UV_PARAM_OBJ_NULL(loop, php_uv_loop_t, uv_loop_ce)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	PHP_UV_INIT_UV_EX(uv, uv_check_ce, uv_check_init);

	RETURN_OBJ(&uv->std);
}
/* }}} */

/* {{{ proto void uv_check_start(UVCheck $handle, callable(UVCheck $handle) $callback)
*/
PHP_FUNCTION(uv_check_start)
{
	php_uv_t *uv;
	int r;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	PHP_UV_DEBUG_PRINT("uv_check_start");

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_check_ce)
		Z_PARAM_FUNC(fci, fcc)
	ZEND_PARSE_PARAMETERS_END();

	if (uv_is_active(&uv->uv.handle)) {
		php_error_docref(NULL, E_WARNING, "passed uv check resource has already started");
		RETURN_FALSE;
	}

	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_check_start, uv);

	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_CHECK_CB);

	r = uv_check_start(&uv->uv.check, php_uv_check_cb);

	RETURN_LONG(r);
}
/* }}} */

/* {{{ proto void uv_check_stop(UVCheck $handle)
*/
PHP_FUNCTION(uv_check_stop)
{
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_check_ce)
	ZEND_PARSE_PARAMETERS_END();

	if (!uv_is_active(&uv->uv.handle)) {
		php_error_docref(NULL, E_NOTICE, "passed uv_check resource hasn't start yet.");
		RETURN_FALSE;
	}

	uv_check_stop(&uv->uv.check);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_check_stop, uv);
	OBJ_RELEASE(&uv->std);
}
/* }}} */


/* {{{ proto UVAsync uv_async_init(UVLoop $loop, callable(UVAsync $handle) $callback)
*/
PHP_FUNCTION(uv_async_init)
{
	php_uv_loop_t *loop;
	php_uv_t *uv;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(loop, php_uv_loop_t, uv_loop_ce)
		Z_PARAM_FUNC(fci, fcc)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	PHP_UV_INIT_UV_EX(uv, uv_async_ce, uv_async_init, php_uv_async_cb);

	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_ASYNC_CB);

	RETURN_OBJ(&uv->std);
}
/* }}} */

/* {{{ proto void uv_async_send(UVAsync $handle)
*/
PHP_FUNCTION(uv_async_send)
{
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_async_ce)
	ZEND_PARSE_PARAMETERS_END();

	uv_async_send(&uv->uv.async);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_async_send, uv);
}
/* }}} */

/* {{{ proto void uv_queue_work(UVLoop $loop, callable() $callback, callable() $after_callback)
*/
PHP_FUNCTION(uv_queue_work)
{
#if defined(ZTS) && PHP_VERSION_ID < 80000
	int r;
	php_uv_loop_t *loop;
	php_uv_t *uv;
	zend_fcall_info work_fci, after_fci       = empty_fcall_info;
	zend_fcall_info_cache work_fcc, after_fcc = empty_fcall_info_cache;
	php_uv_cb_t *work_cb, *after_cb;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		UV_PARAM_OBJ(loop, php_uv_loop_t, uv_loop_ce)
		Z_PARAM_FUNC(work_fci, work_fcc)
		Z_PARAM_FUNC(after_fci, after_fcc)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_INIT_UV(uv, uv_work_ce);

	php_uv_cb_init(&work_cb, uv, &work_fci, &work_fcc, PHP_UV_WORK_CB);
	php_uv_cb_init(&after_cb, uv, &after_fci, &after_fcc, PHP_UV_AFTER_WORK_CB);

	r = uv_queue_work(&loop->loop, &uv->uv.work, php_uv_work_cb, php_uv_after_work_cb);

	if (r) {
		php_error_docref(NULL, E_ERROR, "uv_queue_work failed");
		PHP_UV_DEINIT_UV(uv);
		return;
	}
#else
	php_error_docref(NULL, E_ERROR, "this PHP doesn't support this uv_queue_work. please rebuild with --enable-maintainer-zts");
#endif
}
/* }}} */

/* {{{ proto void uv_fs_open(UVLoop $loop, string $path, long $flag, long $mode, callable(long|resource $file_or_result) $callback)
*/
PHP_FUNCTION(uv_fs_open)
{
	php_uv_fs_common(UV_FS_OPEN, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */


/* {{{ proto void uv_fs_read(UVLoop $loop, resource $fd, long $offset, long $length, callable(resource $fd, string|long $read) $callback)
*/
PHP_FUNCTION(uv_fs_read)
{
	php_uv_fs_common(UV_FS_READ, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */


/* {{{ proto void uv_fs_close(UVLoop $loop, resource $fd[, callable(bool $success) $callback])
*/
PHP_FUNCTION(uv_fs_close)
{
	php_uv_fs_common(UV_FS_CLOSE, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */


/* {{{ proto void uv_fs_write(UVLoop $loop, resource $fd, string $buffer[, long $offset = -1[, callable(resource $fd, long $result) $callback]])
*/
PHP_FUNCTION(uv_fs_write)
{
	php_uv_fs_common(UV_FS_WRITE, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_fsync(UVLoop $loop, resource $fd[, callable(resource $fd, long $result) $callback])
*/
PHP_FUNCTION(uv_fs_fsync)
{
	php_uv_fs_common(UV_FS_FSYNC, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_fdatasync(UVLoop $loop, resource $fd[, callable(resource $fd, long $result) $callback])
*/
PHP_FUNCTION(uv_fs_fdatasync)
{
	php_uv_fs_common(UV_FS_FDATASYNC, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_ftruncate(UVLoop $loop, resource $fd, long $offset[, callable(resource $fd, long $result) $callback])
*/
PHP_FUNCTION(uv_fs_ftruncate)
{
	php_uv_fs_common(UV_FS_FTRUNCATE, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_mkdir(UVLoop $loop, string $path, long $mode[, callable(long $result) $callback])
*/
PHP_FUNCTION(uv_fs_mkdir)
{
	php_uv_fs_common(UV_FS_MKDIR, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */


/* {{{ proto void uv_fs_rmdir(UVLoop $loop, string $path[, callable(long $result) $callback])
*/
PHP_FUNCTION(uv_fs_rmdir)
{
	php_uv_fs_common(UV_FS_RMDIR, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_unlink(UVLoop $loop, string $path[, callable(long $result) $callback])
*/
PHP_FUNCTION(uv_fs_unlink)
{
	php_uv_fs_common(UV_FS_UNLINK, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_rename(UVLoop $loop, string $from, string $to[, callable(long $result) $callback])
*/
PHP_FUNCTION(uv_fs_rename)
{
	php_uv_fs_common(UV_FS_RENAME, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_utime(UVLoop $loop, string $path, long $utime, long $atime[, callable(long $result) $callback])
*/
PHP_FUNCTION(uv_fs_utime)
{
	php_uv_fs_common(UV_FS_UTIME, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_futime(UVLoop $loop, zval $fd, long $utime, long $atime[, callable(long $result) $callback])
*/
PHP_FUNCTION(uv_fs_futime)
{
	php_uv_fs_common(UV_FS_FUTIME, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_chmod(UVLoop $loop, string $path, long $mode[, callable(long $result) $callback])
*/
PHP_FUNCTION(uv_fs_chmod)
{
	php_uv_fs_common(UV_FS_CHMOD, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */


/* {{{ proto void uv_fs_fchmod(UVLoop $loop, zval $fd, long $mode[, callable(long $result) $callback])
*/
PHP_FUNCTION(uv_fs_fchmod)
{
	php_uv_fs_common(UV_FS_FCHMOD, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */


/* {{{ proto void uv_fs_chown(UVLoop $loop, string $path, long $uid, long $gid[, callable(long $result) $callback])
*/
PHP_FUNCTION(uv_fs_chown)
{
	php_uv_fs_common(UV_FS_CHOWN, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_fchown(UVLoop $loop, zval $fd, long $uid, $long $gid[, callable(long $result) $callback])
*/
PHP_FUNCTION(uv_fs_fchown)
{
	php_uv_fs_common(UV_FS_FCHOWN, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_link(UVLoop $loop, string $from, string $to[, callable(long $result) $callback])
*/
PHP_FUNCTION(uv_fs_link)
{
	php_uv_fs_common(UV_FS_LINK, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */


/* {{{ proto void uv_fs_symlink(UVLoop $loop, string $from, string $to, long $flags[, callable(long $result) $callback])
*/
PHP_FUNCTION(uv_fs_symlink)
{
	php_uv_fs_common(UV_FS_SYMLINK, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_readlink(UVLoop $loop, string $path, callable(string|long $result_or_link_contents) $callback)
*/
PHP_FUNCTION(uv_fs_readlink)
{
	php_uv_fs_common(UV_FS_READLINK, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_stat(UVLoop $loop, string $path, callable(long|array $result_or_stat) $callback)
*/
PHP_FUNCTION(uv_fs_stat)
{
	php_uv_fs_common(UV_FS_STAT, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_lstat(UVLoop $loop, string $path, callable(long|array $result_or_stat) $callback)
*/
PHP_FUNCTION(uv_fs_lstat)
{
	php_uv_fs_common(UV_FS_LSTAT, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_fstat(UVLoop $loop, resource $fd, callable(resource $fd, array $stat) $callback)
*/
PHP_FUNCTION(uv_fs_fstat)
{
	php_uv_fs_common(UV_FS_FSTAT, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */


/* {{{ proto void uv_fs_readdir(UVLoop $loop, string $path, callable(long|array $result_or_dir_contents) $callback[, long $flags = 0])
*/
PHP_FUNCTION(uv_fs_readdir)
{
	php_error_docref(NULL, E_DEPRECATED, "Use uv_fs_scandir() instead of uv_fs_readdir()");
	php_uv_fs_common(UV_FS_SCANDIR, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_scandir(UVLoop $loop, string $path, callable(long|array $result_or_dir_contents) $callback[, long $flags = 0])
 *  */
PHP_FUNCTION(uv_fs_scandir)
{
    php_uv_fs_common(UV_FS_SCANDIR, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto void uv_fs_sendfile(UVLoop $loop, resource $in_fd, resource $out_fd, long $offset, long $length[, callable(resource $out_fd, long $result) $callback])
*/
PHP_FUNCTION(uv_fs_sendfile)
{
	php_uv_fs_common(UV_FS_SENDFILE, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto UVFsEvent uv_fs_event_init(UVLoop $loop, string $path, callable(UVFsEvent $handle, string|null $filename, long $events, long $status) $callback[, long $flags = 0])
*/
PHP_FUNCTION(uv_fs_event_init)
{
	int error;
	php_uv_loop_t *loop;
	php_uv_t *uv;
	zend_string *path;
	zend_long flags = 0;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(3, 4)
		UV_PARAM_OBJ(loop, php_uv_loop_t, uv_loop_ce)
		Z_PARAM_STR(path)
		Z_PARAM_FUNC(fci, fcc)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(flags)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	PHP_UV_INIT_UV_EX(uv, uv_fs_event_ce, uv_fs_event_init);

	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_FS_EVENT_CB);

	error = uv_fs_event_start(&uv->uv.fs_event, php_uv_fs_event_cb, path->val, flags);
	if (error < 0) {
		php_error_docref(NULL, E_ERROR, "uv_fs_event_start failed");
		OBJ_RELEASE(&uv->std);
		return;
	}

	RETURN_OBJ(&uv->std);
}
/* }}} */

/* {{{ proto UVTty uv_tty_init(UVLoop $loop, resource $fd, long $readable)
*/
PHP_FUNCTION(uv_tty_init)
{
	zval *zstream;
	php_uv_loop_t *loop;
	php_uv_t *uv;
	zend_long readable = 1;
	unsigned long fd;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		UV_PARAM_OBJ(loop, php_uv_loop_t, uv_loop_ce)
		Z_PARAM_RESOURCE(zstream)
		Z_PARAM_LONG(readable)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	fd = php_uv_zval_to_fd(zstream);
	PHP_UV_INIT_UV_EX(uv, uv_tty_ce, uv_tty_init, fd, readable);
	PHP_UV_CHECK_VALID_FD(fd, zstream);

	RETURN_OBJ(&uv->std);
}
/* }}} */


/* {{{ proto long uv_tty_get_winsize(UVTty $tty, long &$width, long &$height)
*/
PHP_FUNCTION(uv_tty_get_winsize)
{
	php_uv_t *uv;
	zval *w, *h = NULL;
	int error, width, height = 0;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		UV_PARAM_OBJ(uv, php_uv_t, uv_tty_ce)
		Z_PARAM_ZVAL_EX(w, 0, 1)
		Z_PARAM_ZVAL_EX(h, 0, 1)
	ZEND_PARSE_PARAMETERS_END();

	error = uv_tty_get_winsize(&uv->uv.tty, &width, &height);

	zval_ptr_dtor(w);
	zval_ptr_dtor(h);

	ZVAL_LONG(w, width);
	ZVAL_LONG(h, height);

	RETURN_LONG(error);
}
/* }}} */


/* {{{ proto long uv_tty_set_mode(UVTty $tty, long $mode)
*/
PHP_FUNCTION(uv_tty_set_mode)
{
	php_uv_t *uv;
	zend_long mode, error = 0;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_tty_ce)
		Z_PARAM_LONG(mode)
	ZEND_PARSE_PARAMETERS_END();

	error = uv_tty_set_mode(&uv->uv.tty, mode);
	RETURN_LONG(error);
}
/* }}} */

/* {{{ proto void uv_tty_reset_mode(void)
*/
PHP_FUNCTION(uv_tty_reset_mode)
{
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	uv_tty_reset_mode();
}
/* }}} */

/* {{{ proto void uv_tcp_simultaneous_accepts(UVTcp $handle, bool $enable)
 */
PHP_FUNCTION(uv_tcp_simultaneous_accepts)
{
	php_uv_t *uv;
	zend_bool enable;
	zend_long error = 0;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(uv, php_uv_t, uv_tcp_ce)
		Z_PARAM_BOOL(enable)
	ZEND_PARSE_PARAMETERS_END();

	error = uv_tcp_simultaneous_accepts(&uv->uv.tcp, enable);
	RETURN_LONG(error);
}
/* }}} */

/* {{{ proto string uv_tcp_getsockname(UVTcp $uv_sock)
*/
PHP_FUNCTION(uv_tcp_getsockname)
{
	php_uv_socket_getname(1, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto string uv_tcp_getpeername(UVTcp $uv_sock)
*/
PHP_FUNCTION(uv_tcp_getpeername)
{
	php_uv_socket_getname(2, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto string uv_udp_getsockname(UVUdp $uv_sock)
*/
PHP_FUNCTION(uv_udp_getsockname)
{
	php_uv_socket_getname(3, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */


/* {{{ proto long uv_resident_set_memory(void)
*/
PHP_FUNCTION(uv_resident_set_memory)
{
	size_t rss;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	uv_resident_set_memory(&rss);

	RETURN_LONG(rss);
}
/* }}} */

/* {{{ proto string uv_ip4_name(UVSockAddr $address)
*/
PHP_FUNCTION(uv_ip4_name)
{
	php_uv_ip_common(1, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto string uv_ip6_name(UVSockAddr $address)
*/
PHP_FUNCTION(uv_ip6_name)
{
	php_uv_ip_common(2, INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto UVPoll uv_poll_init(UVLoop $loop, resource $fd)
*/
PHP_FUNCTION(uv_poll_init)
{
	zval *zstream;
	php_uv_loop_t *loop;
	php_uv_t *uv;
	unsigned long fd = 0;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		UV_PARAM_OBJ(loop, php_uv_loop_t, uv_loop_ce)
		Z_PARAM_RESOURCE(zstream)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	fd = php_uv_zval_to_valid_poll_fd(zstream);
#ifdef PHP_WIN32
	PHP_UV_INIT_UV_EX(uv, uv_poll_ce, uv_poll_init_socket, (uv_os_sock_t) fd);
#else
	PHP_UV_INIT_UV_EX(uv, uv_poll_ce, uv_poll_init, fd);
#endif
	PHP_UV_CHECK_VALID_FD(fd, zstream);

	uv->sock = fd;
	PHP_UV_DEBUG_PRINT("uv_poll_init: resource: %p\n", uv);

	RETURN_OBJ(&uv->std);
}

/* }}} */


/* {{{ proto void uv_poll_start(UVPoll $handle, long $events, callable(UVPoll $handle, long $status, long $events, resource $fd) $callback)
*/
PHP_FUNCTION(uv_poll_start)
{
	php_uv_t *uv;
	zend_long events = 0;
	int error;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		UV_PARAM_OBJ(uv, php_uv_t, uv_poll_ce)
		Z_PARAM_LONG(events)
		Z_PARAM_FUNC(fci, fcc)
	ZEND_PARSE_PARAMETERS_END();

	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_POLL_CB);
	if (!uv_is_active(&uv->uv.handle)) {
		PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_poll_start, uv);
		GC_ADDREF(&uv->std);
	}

	error = uv_poll_start(&uv->uv.poll, events, php_uv_poll_cb);
	if (error) {
		php_error_docref(NULL, E_ERROR, "uv_poll_start failed");
		return;
	}
}
/* }}} */

/* {{{ proto void uv_poll_stop(UVPoll $poll)
*/
PHP_FUNCTION(uv_poll_stop)
{
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_poll_ce)
	ZEND_PARSE_PARAMETERS_END();

	if (!uv_is_active((uv_handle_t *) &uv->uv.poll)) {
		return;
	}

	uv_poll_stop(&uv->uv.poll);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_poll_stop, uv);
	OBJ_RELEASE(&uv->std);
}
/* }}} */

/* {{{ proto UVFsPoll uv_fs_poll_init([UVLoop $loop = uv_default_loop()])
*/
PHP_FUNCTION(uv_fs_poll_init)
{
	php_uv_loop_t *loop = NULL;
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		UV_PARAM_OBJ_NULL(loop, php_uv_loop_t, uv_loop_ce)
	ZEND_PARSE_PARAMETERS_END();

	PHP_UV_FETCH_UV_DEFAULT_LOOP(loop);
	PHP_UV_INIT_UV_EX(uv, uv_fs_poll_ce, uv_fs_poll_init);

	RETURN_OBJ(&uv->std);
}
/* }}} */

/* {{{ proto uv uv_fs_poll_start(UVFsPoll $handle, callable(UVFsPoll $handle, long $status, array $prev_stat, array $cur_stat) $callback, string $path, long $interval)
*/
PHP_FUNCTION(uv_fs_poll_start)
{
	php_uv_t *uv;
	zend_string *path;
	zend_long interval = 0;
	int error;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	php_uv_cb_t *cb;

	ZEND_PARSE_PARAMETERS_START(4, 4)
		UV_PARAM_OBJ(uv, php_uv_t, uv_fs_poll_ce)
		Z_PARAM_FUNC(fci, fcc)
		Z_PARAM_STR(path)
		Z_PARAM_LONG(interval)
	ZEND_PARSE_PARAMETERS_END();

	php_uv_cb_init(&cb, uv, &fci, &fcc, PHP_UV_FS_POLL_CB);
	GC_ADDREF(&uv->std);
	PHP_UV_DEBUG_OBJ_ADD_REFCOUNT(uv_fs_poll_start, uv);

	error = uv_fs_poll_start(&uv->uv.fs_poll, php_uv_fs_poll_cb, (const char*)path->val, interval);
	if (error) {
		php_error_docref(NULL, E_ERROR, "uv_fs_poll_start failed");
		OBJ_RELEASE(&uv->std);
	}
}
/* }}} */

/* {{{ proto void uv_fs_poll_stop(UVFsPoll $poll)
*/
PHP_FUNCTION(uv_fs_poll_stop)
{
	php_uv_t *uv;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		UV_PARAM_OBJ(uv, php_uv_t, uv_fs_poll_ce)
	ZEND_PARSE_PARAMETERS_END();

	if (!uv_is_active(&uv->uv.handle)) {
		return;
	}

	uv_fs_poll_stop(&uv->uv.fs_poll);

	PHP_UV_DEBUG_OBJ_DEL_REFCOUNT(uv_fs_poll_stop, uv);
	OBJ_RELEASE(&uv->std);
}
/* }}} */




static zend_function_entry uv_functions[] = {
	/* general */
	PHP_FE(uv_update_time,              arginfo_uv_update_time)
	PHP_FE(uv_ref,                      arginfo_uv_ref)
	PHP_FE(uv_unref,                    arginfo_uv_unref)
	PHP_FE(uv_loop_new,                 arginfo_void)
	PHP_FE(uv_default_loop,             arginfo_void)
	PHP_FE(uv_stop,                     arginfo_uv_stop)
	PHP_FE(uv_run,                      arginfo_uv_run)
	PHP_FE(uv_ip4_addr,                 arginfo_uv_ip4_addr)
	PHP_FE(uv_ip6_addr,                 arginfo_uv_ip6_addr)
	PHP_FE(uv_ip4_name,                 arginfo_uv_ip4_name)
	PHP_FE(uv_ip6_name,                 arginfo_uv_ip6_name)
	PHP_FE(uv_write,                    arginfo_uv_write)
	PHP_FE(uv_write2,                   arginfo_uv_write2)
	PHP_FE(uv_shutdown,                 arginfo_uv_shutdown)
	PHP_FE(uv_close,                    arginfo_uv_close)
	PHP_FE(uv_now,                      arginfo_uv_now)
	PHP_FE(uv_loop_delete,              arginfo_uv_loop_delete)
	PHP_FE(uv_read_start,               arginfo_uv_read_start)
	PHP_FE(uv_read_stop,                arginfo_uv_read_stop)
	PHP_FE(uv_err_name,                 arginfo_uv_err_name)
	PHP_FE(uv_strerror,                 arginfo_uv_strerror)
	PHP_FE(uv_is_active,                arginfo_uv_is_active)
	PHP_FE(uv_is_closing,               arginfo_uv_is_closing)
	PHP_FE(uv_is_readable,              arginfo_uv_is_readable)
	PHP_FE(uv_is_writable,              arginfo_uv_is_writable)
	PHP_FE(uv_walk,                     arginfo_uv_walk)
	PHP_FE(uv_guess_handle,             arginfo_uv_guess_handle)
	/* idle */
	PHP_FE(uv_idle_init,                arginfo_uv_idle_init)
	PHP_FE(uv_idle_start,               arginfo_uv_idle_start)
	PHP_FE(uv_idle_stop,                arginfo_uv_idle_stop)
	/* timer */
	PHP_FE(uv_timer_init,               arginfo_uv_timer_init)
	PHP_FE(uv_timer_start,              arginfo_uv_timer_start)
	PHP_FE(uv_timer_stop,               arginfo_uv_timer_stop)
	PHP_FE(uv_timer_again,              arginfo_uv_timer_again)
	PHP_FE(uv_timer_set_repeat,         arginfo_uv_timer_set_repeat)
	PHP_FE(uv_timer_get_repeat,         arginfo_uv_timer_get_repeat)
	/* tcp */
	PHP_FE(uv_tcp_init,                 arginfo_uv_tcp_init)
	PHP_FE(uv_tcp_open,                 arginfo_uv_tcp_open)
	PHP_FE(uv_tcp_nodelay,              arginfo_uv_tcp_nodelay)
	PHP_FE(uv_tcp_bind,                 arginfo_uv_tcp_bind)
	PHP_FE(uv_tcp_bind6,                arginfo_uv_tcp_bind6)
	PHP_FE(uv_listen,                   arginfo_uv_listen)
	PHP_FE(uv_accept,                   arginfo_uv_accept)
	PHP_FE(uv_tcp_connect,              arginfo_uv_tcp_connect)
	PHP_FE(uv_tcp_connect6,             arginfo_uv_tcp_connect6)
	/* udp */
	PHP_FE(uv_udp_init,                 arginfo_uv_udp_init)
	PHP_FE(uv_udp_open,                 arginfo_uv_udp_open)
	PHP_FE(uv_udp_bind,                 arginfo_uv_udp_bind)
	PHP_FE(uv_udp_bind6,                arginfo_uv_udp_bind6)
	PHP_FE(uv_udp_set_multicast_loop,   arginfo_uv_udp_set_multicast_loop)
	PHP_FE(uv_udp_set_multicast_ttl,    arginfo_uv_udp_set_multicast_ttl)
	PHP_FE(uv_udp_send,                 arginfo_uv_udp_send)
	PHP_FE(uv_udp_send6,                arginfo_uv_udp_send6)
	PHP_FE(uv_udp_recv_start,           arginfo_uv_udp_recv_start)
	PHP_FE(uv_udp_recv_stop,            arginfo_uv_udp_recv_stop)
	PHP_FE(uv_udp_set_membership,       arginfo_uv_udp_set_membership)
	PHP_FE(uv_udp_set_broadcast,        arginfo_uv_udp_set_broadcast)
	/* poll */
	PHP_FE(uv_poll_init,                arginfo_uv_poll_init)
	PHP_FALIAS(uv_poll_init_socket,     uv_poll_init,  arginfo_uv_poll_init)
	PHP_FE(uv_poll_start,               arginfo_uv_poll_start)
	PHP_FE(uv_poll_stop,                arginfo_uv_poll_stop)
	PHP_FE(uv_fs_poll_init,             arginfo_uv_fs_poll_init)
	PHP_FE(uv_fs_poll_start,            arginfo_uv_fs_poll_start)
	PHP_FE(uv_fs_poll_stop,             arginfo_uv_fs_poll_stop)
	/* other network functions */
	PHP_FE(uv_tcp_getsockname,          arginfo_uv_tcp_getsockname)
	PHP_FE(uv_tcp_getpeername,          arginfo_uv_tcp_getpeername)
	PHP_FE(uv_udp_getsockname,          arginfo_uv_udp_getsockname)
	PHP_FE(uv_tcp_simultaneous_accepts, arginfo_uv_tcp_simultaneous_accepts)
	/* pipe */
	PHP_FE(uv_pipe_init,                arginfo_uv_pipe_init)
	PHP_FE(uv_pipe_bind,                arginfo_uv_pipe_bind)
	PHP_FE(uv_pipe_open,                arginfo_uv_pipe_open)
	PHP_FE(uv_pipe_connect,             arginfo_uv_pipe_connect)
	PHP_FE(uv_pipe_pending_instances,   arginfo_uv_pipe_pending_instances)
	PHP_FE(uv_pipe_pending_count,       arginfo_uv_pipe_pending_count)
	PHP_FE(uv_pipe_pending_type,        arginfo_uv_pipe_pending_type)
	PHP_FE(uv_stdio_new,                arginfo_void)
	/* spawn */
	PHP_FE(uv_spawn,                    arginfo_uv_spawn)
	PHP_FE(uv_process_kill,             arginfo_uv_process_kill)
	PHP_FE(uv_process_get_pid,          arginfo_uv_process_get_pid)
	PHP_FE(uv_kill,                     arginfo_uv_kill)
	/* c-ares */
	PHP_FE(uv_getaddrinfo,              arginfo_uv_getaddrinfo)
	/* rwlock */
	PHP_FE(uv_rwlock_init,              arginfo_void)
	PHP_FE(uv_rwlock_rdlock,            arginfo_uv_rwlock_rdlock)
	PHP_FE(uv_rwlock_tryrdlock,         arginfo_uv_rwlock_tryrdlock)
	PHP_FE(uv_rwlock_rdunlock,          arginfo_uv_rwlock_rdunlock)
	PHP_FE(uv_rwlock_wrlock,            arginfo_uv_rwlock_wrlock)
	PHP_FE(uv_rwlock_trywrlock,         arginfo_uv_rwlock_trywrlock)
	PHP_FE(uv_rwlock_wrunlock,          arginfo_uv_rwlock_wrunlock)
	/* mutex */
	PHP_FE(uv_mutex_init,               arginfo_void)
	PHP_FE(uv_mutex_lock,               arginfo_uv_mutex_lock)
	PHP_FE(uv_mutex_trylock,            arginfo_uv_mutex_trylock)
	PHP_FE(uv_mutex_unlock,             arginfo_uv_mutex_unlock)
	/* semaphore */
	PHP_FE(uv_sem_init,                 arginfo_uv_sem_init)
	PHP_FE(uv_sem_post,                 arginfo_uv_sem_post)
	PHP_FE(uv_sem_wait,                 arginfo_uv_sem_wait)
	PHP_FE(uv_sem_trywait,              arginfo_uv_sem_trywait)
	/* prepare (before poll hook) */
	PHP_FE(uv_prepare_init,             arginfo_uv_prepare_init)
	PHP_FE(uv_prepare_start,            arginfo_uv_prepare_start)
	PHP_FE(uv_prepare_stop,             arginfo_uv_prepare_stop)
	/* check (after poll hook) */
	PHP_FE(uv_check_init,               arginfo_uv_check_init)
	PHP_FE(uv_check_start,              arginfo_uv_check_start)
	PHP_FE(uv_check_stop,               arginfo_uv_check_stop)
	/* async */
	PHP_FE(uv_async_init,               arginfo_uv_async_init)
	PHP_FE(uv_async_send,               arginfo_uv_async_send)
	/* queue (does not work yet) */
#if PHP_VERSION_ID < 80000
	PHP_FE(uv_queue_work,               NULL)
#endif
	/* fs */
	PHP_FE(uv_fs_open,                  arginfo_uv_fs_open)
	PHP_FE(uv_fs_read,                  arginfo_uv_fs_read)
	PHP_FE(uv_fs_write,                 arginfo_uv_fs_write)
	PHP_FE(uv_fs_close,                 arginfo_uv_fs_close)
	PHP_FE(uv_fs_fsync,                 arginfo_uv_fs_fsync)
	PHP_FE(uv_fs_fdatasync,             arginfo_uv_fs_fdatasync)
	PHP_FE(uv_fs_ftruncate,             arginfo_uv_fs_ftruncate)
	PHP_FE(uv_fs_mkdir,                 arginfo_uv_fs_mkdir)
	PHP_FE(uv_fs_rmdir,                 arginfo_uv_fs_rmdir)
	PHP_FE(uv_fs_unlink,                arginfo_uv_fs_unlink)
	PHP_FE(uv_fs_rename,                arginfo_uv_fs_rename)
	PHP_FE(uv_fs_utime,                 arginfo_uv_fs_utime)
	PHP_FE(uv_fs_futime,                arginfo_uv_fs_futime)
	PHP_FE(uv_fs_chmod,                 arginfo_uv_fs_chmod)
	PHP_FE(uv_fs_fchmod,                arginfo_uv_fs_fchmod)
	PHP_FE(uv_fs_chown,                 arginfo_uv_fs_chown)
	PHP_FE(uv_fs_fchown,                arginfo_uv_fs_fchown)
	PHP_FE(uv_fs_link,                  arginfo_uv_fs_link)
	PHP_FE(uv_fs_symlink,               arginfo_uv_fs_symlink)
	PHP_FE(uv_fs_readlink,              arginfo_uv_fs_readlink)
	PHP_FE(uv_fs_stat,                  arginfo_uv_fs_stat)
	PHP_FE(uv_fs_lstat,                 arginfo_uv_fs_lstat)
	PHP_FE(uv_fs_fstat,                 arginfo_uv_fs_fstat)
	PHP_FE(uv_fs_readdir,               arginfo_uv_fs_readdir)
	PHP_FE(uv_fs_scandir,               arginfo_uv_fs_scandir)
	PHP_FE(uv_fs_sendfile,              arginfo_uv_fs_sendfile)
	PHP_FE(uv_fs_event_init,            arginfo_uv_fs_event_init)
	/* tty */
	PHP_FE(uv_tty_init,                 arginfo_uv_tty_init)
	PHP_FE(uv_tty_get_winsize,          arginfo_uv_tty_get_winsize)
	PHP_FE(uv_tty_set_mode,             arginfo_void)
	PHP_FE(uv_tty_reset_mode,           arginfo_void)
	/* info */
	PHP_FE(uv_loadavg,                  arginfo_void)
	PHP_FE(uv_uptime,                   arginfo_void)
	PHP_FE(uv_cpu_info,                 arginfo_void)
	PHP_FE(uv_interface_addresses,      arginfo_void)
	PHP_FE(uv_get_free_memory,          arginfo_void)
	PHP_FE(uv_get_total_memory,         arginfo_void)
	PHP_FE(uv_hrtime,                   arginfo_void)
	PHP_FE(uv_exepath,                  arginfo_void)
	PHP_FE(uv_cwd,                      arginfo_void)
	PHP_FE(uv_chdir,                    arginfo_uv_chdir)
	PHP_FE(uv_resident_set_memory,      arginfo_void)
	/* signal handling */
	PHP_FE(uv_signal_init,              arginfo_uv_signal_init)
	PHP_FE(uv_signal_start,             arginfo_uv_signal_start)
	PHP_FE(uv_signal_stop,              arginfo_uv_signal_stop)
	{0}
};

PHP_MINFO_FUNCTION(uv)
{
	char uv_version[20];

	sprintf(uv_version, "%d.%d",UV_VERSION_MAJOR, UV_VERSION_MINOR);

	php_printf("PHP libuv Extension\n");
	php_info_print_table_start();
	php_info_print_table_header(2,"libuv Support",  "enabled");
	php_info_print_table_row(2,"Version", PHP_UV_VERSION);
	php_info_print_table_row(2,"libuv Version", uv_version);
	php_info_print_table_end();
}

static PHP_GINIT_FUNCTION(uv)
{
#if defined(COMPILE_DL_UV) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	uv_globals->default_loop = NULL;
}

zend_module_entry uv_module_entry = {
	STANDARD_MODULE_HEADER,
	"uv",
	uv_functions,					/* Functions */
	PHP_MINIT(uv),	/* MINIT */
	NULL,					/* MSHUTDOWN */
	NULL,					/* RINIT */
	PHP_RSHUTDOWN(uv),		/* RSHUTDOWN */
	PHP_MINFO(uv),	/* MINFO */
	PHP_UV_VERSION,
	PHP_MODULE_GLOBALS(uv),
	PHP_GINIT(uv),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};


#ifdef COMPILE_DL_UV
ZEND_GET_MODULE(uv)
#endif

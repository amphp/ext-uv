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

void php_uv_init(zend_class_entry *uv_class_entry)
{
	zend_declare_class_constant_long(uv_class_entry, "RUN_DEFAULT",  sizeof("RUN_DEFAULT")-1, UV_RUN_DEFAULT TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "RUN_ONCE",  sizeof("RUN_ONCE")-1, UV_RUN_ONCE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "RUN_NOWAIT",  sizeof("RUN_NOWAIT")-1, UV_RUN_NOWAIT TSRMLS_CC);

	zend_declare_class_constant_long(uv_class_entry, "CHANGE",  sizeof("CHANGE")-1, UV_CHANGE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "RENAME",  sizeof("RENAME")-1, UV_RENAME TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "READABLE",sizeof("READABLE")-1, UV_READABLE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "WRITABLE",sizeof("WRITABLE")-1, UV_WRITABLE TSRMLS_CC);

	zend_declare_class_constant_long(uv_class_entry, "O_RDONLY",  sizeof("O_RDONLY")-1, O_RDONLY TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "O_WRONLY", sizeof("O_WRONLY")-1, O_WRONLY TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "O_RDWR",    sizeof("O_RDWR")-1,   O_RDWR TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "O_CREAT",   sizeof("O_CREAT")-1,  O_CREAT TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "O_EXCL",    sizeof("O_EXCL")-1,   O_EXCL TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "O_TRUNC",   sizeof("O_TRUNC")-1,  O_TRUNC TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "O_APPEND",  sizeof("O_APPEND")-1, O_APPEND TSRMLS_CC);

	zend_declare_class_constant_long(uv_class_entry, "S_IFDIR",  sizeof("S_IFDIR")-1, S_IFDIR TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IFREG",  sizeof("S_IFREG")-1, S_IFREG TSRMLS_CC);

#ifndef PHP_WIN32
	zend_declare_class_constant_long(uv_class_entry, "O_NOCTTY",  sizeof("O_NOCTTY")-1, O_NOCTTY TSRMLS_CC);

	zend_declare_class_constant_long(uv_class_entry, "S_IRWXU",  sizeof("S_IRWXU")-1, S_IRWXU TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IRUSR",  sizeof("S_IRUSR")-1, S_IRUSR TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IWUSR",  sizeof("S_IWUSR")-1, S_IWUSR TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IXUSR",  sizeof("S_IXUSR")-1, S_IXUSR TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IRWXG",  sizeof("S_IRWXG")-1, S_IRWXG TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IRGRP",  sizeof("S_IRGRP")-1, S_IRGRP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IWGRP",  sizeof("S_IWGRP")-1, S_IWGRP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IXGRP",  sizeof("S_IXGRP")-1, S_IXGRP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IRWXO",  sizeof("S_IRWXO")-1, S_IRWXO TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IROTH",  sizeof("S_IROTH")-1, S_IROTH TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IWOTH",  sizeof("S_IWOTH")-1, S_IWOTH TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IXOTH",  sizeof("S_IXOTH")-1, S_IXOTH TSRMLS_CC);

	/* Non-windows Signal Constants */
	zend_declare_class_constant_long(uv_class_entry, "SIG_IGN",  sizeof("SIG_IGN")-1, (long) SIG_IGN TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIG_DFL",  sizeof("SIG_DFL")-1, (long) SIG_DFL TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIG_ERR",  sizeof("SIG_ERR")-1, (long) SIG_ERR TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGHUP",   sizeof("SIGHUP")-1, (long) SIGHUP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGINT",   sizeof("SIGINT")-1, (long) SIGINT TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGQUIT",  sizeof("SIGQUIT")-1, (long) SIGQUIT TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGILL",   sizeof("SIGILL")-1, (long) SIGILL TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGTRAP",  sizeof("SIGTRAP")-1, (long) SIGTRAP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGABRT",  sizeof("SIGABRT")-1, (long) SIGABRT TSRMLS_CC);
#ifdef SIGIOT
	zend_declare_class_constant_long(uv_class_entry, "SIGIOT",   sizeof("SIGIOT")-1, (long) SIGIOT TSRMLS_CC);
#endif
	zend_declare_class_constant_long(uv_class_entry, "SIGBUS",   sizeof("SIGBUS")-1, (long) SIGBUS TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGFPE",   sizeof("SIGFPE")-1, (long) SIGFPE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGKILL",  sizeof("SIGKILL")-1, (long) SIGKILL TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGUSR1",  sizeof("SIGUSR1")-1, (long) SIGUSR1 TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGSEGV",  sizeof("SIGSEGV")-1, (long) SIGSEGV TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGUSR2",  sizeof("SIGUSR2")-1, (long) SIGUSR2 TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGPIPE",  sizeof("SIGPIPE")-1, (long) SIGPIPE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGALRM",  sizeof("SIGALRM")-1, (long) SIGALRM TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGTERM",  sizeof("SIGTERM")-1, (long) SIGTERM TSRMLS_CC);
#ifdef SIGSTKFLT
	zend_declare_class_constant_long(uv_class_entry, "SIGSTKFLT",sizeof("SIGSTKFLT")-1, (long) SIGSTKFLT TSRMLS_CC);
#endif
#ifdef SIGCLD
	zend_declare_class_constant_long(uv_class_entry, "SIGCLD",   sizeof("SIGCLD")-1, (long) SIGCLD TSRMLS_CC);
#endif
#ifdef SIGCHLD
	zend_declare_class_constant_long(uv_class_entry, "SIGCHLD",  sizeof("SIGCHLD")-1, (long) SIGCHLD TSRMLS_CC);
#endif
	zend_declare_class_constant_long(uv_class_entry, "SIGCONT",  sizeof("SIGCONT")-1, (long) SIGCONT TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGSTOP",  sizeof("SIGSTOP")-1, (long) SIGSTOP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGTSTP",  sizeof("SIGTSTP")-1, (long) SIGTSTP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGTTIN",  sizeof("SIGTTIN")-1, (long) SIGTTIN TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGTTOU",  sizeof("SIGTTOU")-1, (long) SIGTTOU TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGURG",   sizeof("SIGURG")-1, (long) SIGURG  TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGXCPU",  sizeof("SIGXCPU")-1, (long) SIGXCPU TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGXFSZ",  sizeof("SIGXFSZ")-1, (long) SIGXFSZ TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGVTALRM",sizeof("SIGVTALRM")-1, (long) SIGVTALRM TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGPROF",  sizeof("SIGPROF")-1, (long) SIGPROF TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGWINCH", sizeof("SIGWINCH")-1, (long) SIGWINCH TSRMLS_CC);
#ifdef SIGPOLL
	zend_declare_class_constant_long(uv_class_entry, "SIGPOLL",  sizeof("SIGPOLL")-1, (long) SIGPOLL TSRMLS_CC);
#endif
	zend_declare_class_constant_long(uv_class_entry, "SIGIO",    sizeof("SIGIO")-1, (long) SIGIO TSRMLS_CC);
#ifdef SIGPWR
	zend_declare_class_constant_long(uv_class_entry, "SIGPWR",   sizeof("SIGPWR")-1, (long) SIGPWR TSRMLS_CC);
#endif
#ifdef SIGSYS
	zend_declare_class_constant_long(uv_class_entry, "SIGSYS",   sizeof("SIGSYS")-1, (long) SIGSYS TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGBABY",  sizeof("SIGBABY")-1, (long) SIGSYS TSRMLS_CC);
#endif

#else
	zend_declare_class_constant_long(uv_class_entry, "S_IRWXU",  sizeof("S_IRWXU")-1, _S_IWRITE | _S_IREAD TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IRUSR",  sizeof("S_IRUSR")-1, _S_IREAD TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IWUSR",  sizeof("S_IWUSR")-1, _S_IWRITE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IXUSR",  sizeof("S_IXUSR")-1, 0 TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IRWXG",  sizeof("S_IRWXG")-1, _S_IWRITE | _S_IREAD TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IRGRP",  sizeof("S_IRGRP")-1, _S_IREAD TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IWGRP",  sizeof("S_IWGRP")-1, _S_IWRITE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IXGRP",  sizeof("S_IXGRP")-1, 0 TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IRWXO",  sizeof("S_IRWXO")-1, _S_IWRITE | _S_IREAD TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IROTH",  sizeof("S_IROTH")-1, _S_IREAD TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IWOTH",  sizeof("S_IWOTH")-1, _S_IWRITE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "S_IXOTH",  sizeof("S_IXOTH")-1, 0 TSRMLS_CC);

	/* Windows Signal Constants */
	zend_declare_class_constant_long(uv_class_entry, "SIGBREAK", sizeof("SIGBREAK")-1, (long) SIGBREAK TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGINT",   sizeof("SIGINT")-1, (long) SIGINT TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGHUP",   sizeof("SIGHUP")-1, (long) SIGHUP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "SIGWINCH", sizeof("SIGWINCH")-1, (long) SIGWINCH TSRMLS_CC);
#endif

	zend_declare_class_constant_long(uv_class_entry, "AF_INET",  sizeof("AF_INET")-1, AF_INET TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "AF_INET6",  sizeof("AF_INET6")-1, AF_INET6 TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "AF_UNSPEC",  sizeof("AF_UNSPEC")-1, AF_UNSPEC TSRMLS_CC);

	zend_declare_class_constant_long(uv_class_entry, "LEAVE_GROUP",  sizeof("LEAVE_GROUP")-1, UV_LEAVE_GROUP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry, "JOIN_GROUP",  sizeof("JOIN_GROUP")-1, UV_JOIN_GROUP TSRMLS_CC);

	/* for uv_handle_type */
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_TCP", sizeof("IS_UV_TCP")-1, IS_UV_TCP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_UDP", sizeof("IS_UV_UDP")-1, IS_UV_UDP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_PIPE", sizeof("IS_UV_PIPE")-1, IS_UV_PIPE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_IDLE", sizeof("IS_UV_IDLE")-1, IS_UV_IDLE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_TIMER", sizeof("IS_UV_TIMER")-1, IS_UV_TIMER TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_ASYNC", sizeof("IS_UV_ASYNC")-1, IS_UV_ASYNC TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_LOOP", sizeof("IS_UV_LOOP")-1, IS_UV_LOOP TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_HANDLE", sizeof("IS_UV_HANDLE")-1, IS_UV_HANDLE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_STREAM", sizeof("IS_UV_STREAM")-1, IS_UV_STREAM TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_ADDRINFO", sizeof("IS_UV_ADDRINFO")-1, IS_UV_ADDRINFO TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_PROCESS", sizeof("IS_UV_PROCESS")-1, IS_UV_PROCESS TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_PREPARE", sizeof("IS_UV_PREPARE")-1, IS_UV_PREPARE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_CHECK", sizeof("IS_UV_CHECK")-1, IS_UV_CHECK TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_WORK", sizeof("IS_UV_WORK")-1, IS_UV_WORK TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_FS", sizeof("IS_UV_FS")-1, IS_UV_FS TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_FS_EVENT", sizeof("IS_UV_FS_EVENT")-1, IS_UV_FS_EVENT TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_TTY", sizeof("IS_UV_TTY")-1, IS_UV_TTY TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_FS_POLL", sizeof("IS_UV_FS_POLL")-1, IS_UV_FS_POLL TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "IS_UV_POLL", sizeof("IS_UV_POLL")-1, IS_UV_POLL TSRMLS_CC);

	/* for guess handle */
	zend_declare_class_constant_long(uv_class_entry,  "UNKNOWN_HANDLE", sizeof("UNKNOWN_HANDLE")-1, UV_UNKNOWN_HANDLE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "FILE", sizeof("FILE")-1, UV_FILE TSRMLS_CC);
#define XX(uc, lc) zend_declare_class_constant_long(uv_class_entry,  #uc, sizeof(#uc)-1, UV_##uc TSRMLS_CC);
	UV_HANDLE_TYPE_MAP(XX)
#undef XX
	zend_declare_class_constant_long(uv_class_entry,  "HANDLE_TYPE_MAX", sizeof("HANDLE_TYPE_MAX")-1, UV_HANDLE_TYPE_MAX TSRMLS_CC);


	/* stdio flags */
	zend_declare_class_constant_long(uv_class_entry,  "IGNORE", sizeof("IGNORE")-1, UV_IGNORE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "CREATE_PIPE", sizeof("CREATE_PIPE")-1, UV_CREATE_PIPE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "INHERIT_FD", sizeof("INHERIT_FD")-1, UV_INHERIT_FD TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "INHERIT_STREAM", sizeof("INHERIT_STREAM")-1, UV_INHERIT_STREAM TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "READABLE_PIPE", sizeof("READABLE_PIPE")-1, UV_READABLE_PIPE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "WRITABLE_PIPE", sizeof("WRITABLE_PIPE")-1, UV_WRITABLE_PIPE TSRMLS_CC);
#if UV_VERSION_HEX >= ((1 << 16) | (21 << 8))
	zend_declare_class_constant_long(uv_class_entry,  "OVERLAPPED_PIPE", sizeof("OVERLAPPED_PIPE")-1, UV_OVERLAPPED_PIPE TSRMLS_CC);
#endif

	/* process */
	zend_declare_class_constant_long(uv_class_entry,  "PROCESS_SETUID", sizeof("PROCESS_SETUID")-1, UV_PROCESS_SETUID TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "PROCESS_SETGID", sizeof("PROCESS_SETGID")-1, UV_PROCESS_SETGID TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "PROCESS_WINDOWS_VERBATIM_ARGUMENTS", sizeof("PROCESS_WINDOWS_VERBATIM_ARGUMENTS")-1, UV_PROCESS_WINDOWS_VERBATIM_ARGUMENTS TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "PROCESS_DETACHED", sizeof("PROCESS_DETACHED")-1, UV_PROCESS_DETACHED TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "PROCESS_WINDOWS_HIDE", sizeof("PROCESS_WINDOWS_HIDE")-1, UV_PROCESS_WINDOWS_HIDE TSRMLS_CC);
#if UV_VERSION_HEX >= ((1 << 16) | (24 << 8))
	zend_declare_class_constant_long(uv_class_entry,  "PROCESS_WINDOWS_HIDE_CONSOLE", sizeof("PROCESS_WINDOWS_HIDE_CONSOLE")-1, UV_PROCESS_WINDOWS_HIDE_CONSOLE TSRMLS_CC);
	zend_declare_class_constant_long(uv_class_entry,  "PROCESS_WINDOWS_HIDE_GUI", sizeof("PROCESS_WINDOWS_HIDE_GUI")-1, UV_PROCESS_WINDOWS_HIDE_GUI TSRMLS_CC);
#endif

#define PHP_UV_ERRNO_GEN(name, msg_notused) zend_declare_class_constant_long(uv_class_entry, ZEND_STRL(#name), UV_##name);
	UV_ERRNO_MAP(PHP_UV_ERRNO_GEN)
#undef PHP_UV_ERRNO_GEN
}

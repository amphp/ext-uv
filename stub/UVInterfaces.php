<?php

/**
 * The event loop is the central part of `libuv's` functionality.
 * It takes care of polling for i/o and scheduling callbacks to
 * be run based on different sources of events.
 */
interface uv_loop extends object
{
}

/**
 * Base handle type for `libuv` handles.
 * All handle types (including stream types) subclass
 * - uv_tcp,
 * - uv_udp,
 * - uv_pipe,
 * - ...etc
 *
 * All API functions defined here work with any handle type.
 * `Libuv` handles are not movable. Pointers to handle structures passed
 * to functions must remain valid for the duration of the requested operation.
 * Take care when using stack allocated handles.
 */
interface uv_handle
{
    const UV_UNKNOWN_HANDLE = 0;
    const UV_ASYNC = 1;
    const UV_CHECK = 2;
    const UV_FS_EVENT = 3;
    const UV_FS_POLL = 4;
    const UV_HANDLE = 5;
    const UV_IDLE = 6;
    const UV_NAMED_PIPE = 7;
    const UV_POLL = 8;
    const UV_PREPARE = 9;
    const UV_PROCESS = 10;
    const UV_STREAM = 11;
    const UV_TCP = 12;
    const UV_TIMER = 13;
    const UV_TTY = 14;
    const UV_UDP = 15;
    const UV_SIGNAL = 16;
    const UV_FILE = 17;
    const UV_HANDLE_TYPE_MAX = 18;

    /**
     * Type definition for callback passed to `uv_close()`.
     *
     * @param callable $callback
     * @return void
     */
    public function close(callable $callback): void;

    /**
     * Type of the underlying handle.
     *
     * @return string
     */
    public function type(): string;

    /**
     * Pointer to loop instance the handle is running on.
     *
     * @return uv_loop
     */
    public function loop(): uv_loop;
}

/**
 * Stream handles provide an abstraction of a duplex communication channel.
 * `uv_stream` is an abstract type, `libuv` provides 3 stream implementations
 * in the form of `uv_tcp`, `uv_pipe` and `uv_tty`
 */
interface uv_stream extends uv_handle
{
}

/**
 * TCP handles are used to represent both TCP streams and servers.
 */
interface uv_tcp extends uv_stream
{
}

/**
 * UDP handles encapsulate UDP communication for both clients and servers.
 */
interface uv_udp extends uv_handle
{
}

/**
 * Pipe handles provide an abstraction over streaming files on
 * Unix (including local domain sockets, pipes, and FIFOs) and named pipes on Windows.
 */
interface uv_pipe extends uv_stream
{
}

/**
 * Poll handles are used to watch file descriptors for readability, writability
 * and disconnection similar to the purpose of poll(2).
 *
 * The purpose of poll handles is to enable integrating external libraries that rely on
 * the event loop to signal it about the socket status changes, like c-ares or libssh2.
 * Using `uv_poll` for any other purpose is not recommended; `uv_tcp`, `uv_udp`, etc.
 * provide an implementation that is faster and more scalable than what can be achieved
 * with `uv_poll`, especially on Windows.
 *
 * It is possible that poll handles occasionally signal that a file descriptor is readable
 * or writable even when it isn�t. The user should therefore always be prepared to handle
 * EAGAIN or equivalent when it attempts to read from or write to the fd.
 *
 * It is not okay to have multiple active poll handles for the same socket, this can cause
 * libuv to busyloop or otherwise malfunction.
 *
 * The user should not close a file descriptor while it is being polled by an active poll
 * handle. This can cause the handle to report an error, but it might also start polling
 * another socket. However the fd can be safely closed immediately after a call to
 * uv_poll_stop() or uv_close().
 *
 * Note: On windows only sockets can be polled with poll handles. On Unix any file descriptor that would be accepted by poll(2) can be used.
 *
 * Note: On AIX, watching for disconnection is not supported.
 */
interface uv_poll extends uv_handle
{
}

/**
 * Timer handles are used to schedule callbacks to be called in the future.
 */
interface uv_timer extends uv_handle
{
}

/**
 * Signal handles implement Unix style signal handling on a per-event loop bases.
 *
 * UNIX signal handling on a per-event loop basis. The implementation is not
 * ultra efficient so don't go creating a million event loops with a million
 * signal watchers.
 *
 * Note to Linux users: `SIGRT0` and `SIGRT1` (signals 32 and 33) are used by the
 * NPTL pthreads library to manage threads. Installing watchers for those
 * signals will lead to unpredictable behavior and is strongly discouraged.
 * Future versions of libuv may simply reject them.
 *
 * Some signal support is available on `Windows`:
 *
 *   `SIGINT` is normally delivered when the user presses CTRL+C. However, like
 *   on Unix, it is not generated when terminal raw mode is enabled.
 *
 *   `SIGBREAK` is delivered when the user pressed CTRL+BREAK.
 *
 *   `SIGHUP` is generated when the user closes the console window. On `SIGHUP` the
 *   program is given approximately 10 seconds to perform cleanup. After that
 *   Windows will unconditionally terminate it.
 *
 *   `SIGWINCH` is raised whenever libuv detects that the console has been
 *   resized. `SIGWINCH` is emulated by libuv when the program uses an uv_tty_t
 *   handle to write to the console. `SIGWINCH` may not always be delivered in a
 *   timely manner; libuv will only detect size changes when the cursor is
 *   being moved. When a readable uv_tty_handle is used in raw mode, resizing
 *   the console buffer will also trigger a `SIGWINCH` signal.
 *
 * Watchers for other signals can be successfully created, but these signals
 * are never generated. These signals are: `SIGILL`, `SIGABRT`, `SIGFPE`, `SIGSEGV`,
 * `SIGTERM` and `SIGKILL`.
 *
 * Note that calls to raise() or abort() to programmatically raise a signal are
 * not detected by libuv; these will not trigger a signal watcher.
 */
interface uv_signal extends uv_handle
{
}

/**
 * Process handles will spawn a new process and allow the user to control it and
 * establish communication channels with it using streams.
 */
interface uv_process extends uv_handle
{
}

/**
 * Async handles allow the user to “wakeup” the event loop and get a callback
 * called from another thread.
 */
interface uv_async extends uv_handle
{
}

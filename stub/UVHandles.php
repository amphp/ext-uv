<?php

/**
 * The event loop is the central part of `libuv's` functionality.
 * It takes care of polling for i/o and scheduling callbacks to
 * be run based on different sources of events.
 */
final class UVLoop
{
}

/**
 * Stream handles provide an abstraction of a duplex communication channel.
 * `UVStream` is an abstract type, `libuv` provides 3 stream implementations
 * in the form of `UVTcp`, `UVPipe` and `UVTty`
 */
final class UVStream extends UV
{
}

/**
 * TCP handles are used to represent both TCP streams and servers.
 */
final class UVTcp extends UVStream
{
}

/**
 * UDP handles encapsulate UDP communication for both clients and servers.
 */
final class UVUdp extends UV
{
}

/**
 * Pipe handles provide an abstraction over streaming files on
 * Unix (including local domain sockets, pipes, and FIFOs) and named pipes on Windows.
 */
final class UVPipe extends UVStream
{
}

/**
 * Poll handles are used to watch file descriptors for readability, writability
 * and disconnection similar to the purpose of poll(2).
 *
 * The purpose of poll handles is to enable integrating external libraries that rely on
 * the event loop to signal it about the socket status changes, like c-ares or libssh2.
 * Using `UVPoll` for any other purpose is not recommended; `UVTcp`, `UVUdp`, etc.
 * provide an implementation that is faster and more scalable than what can be achieved
 * with `UVPoll`, especially on Windows.
 *
 * It is possible that poll handles occasionally signal that a file descriptor is readable
 * or writable even when it isn't. The user should therefore always be prepared to handle
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
final class UVPoll extends UV
{
}

/**
 * Timer handles are used to schedule callbacks to be called in the future.
 */
final class UVTimer extends UV
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
final class UVSignal extends UV
{
}

/**
 * Process handles will spawn a new process and allow the user to control it and
 * establish communication channels with it using streams.
 */
final class UVProcess extends UV
{
}

/**
 * Async handles allow the user to wakeup the event loop and get a callback
 * called from another thread.
 */
final class UVAsync extends UV
{
}

/**
 * TTY handles represent a stream for the console.
 */
final class UVTty extends UVStream
{
}

/**
 * Idle handles will run the given callback once per loop iteration, right before
 * the `UVPrepare` handles.
 *
 * `Note:` The notable difference with prepare handles is that when there are active idle
 *  handles, the loop will perform a zero timeout poll instead of blocking for i/o.
 *
 * `Warning:` Despite the name, idle handles will get their callbacks called on every loop
 *  iteration, not when the loop is actually "idle".
 */
final class UVIdle extends UV
{
}

/**
 * Prepare handles will run the given callback once per loop iteration, right before
 * polling for i/o.
 */
final class UVPrepare extends UV
{
}

/**
 * Check handles will run the given callback once per loop iteration, right after
 * polling for i/o.
 */
final class UVCheck extends UV
{
}

/**
 * Stdio is an I/O wrapper to be passed to uv_spawn().
 */
final class UVStdio
{
}

/**
 * Address and port base structure
 */
abstract class UVSockAddr
{
}

/**
 * IPv4 Address and port structure
 */
final class UVSockAddrIPv4 extends UVSockAddr
{
}

/**
 * IPv6 Address and port structure
 */
final class UVSockAddrIPv6 extends UVSockAddr
{
}

/**
 * Lock handle (Lock, Mutex, Semaphore)
 *
 * `libuv` provides cross-platform implementations for multiple threading and synchronization primitives.
 *
 * The API largely follows the pthreads API.
 */
final class UVLock
{
}

/**
 * FS Event handles allow the user to monitor a given path for changes, for example,
 * if the file was renamed or there was a generic change in it.
 *
 * This handle uses the best backend for the job on each platform.
 */
final class UVFsEvent extends UV
{
}

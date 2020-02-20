<?php

/**
 * create a `new` loop handle.
 *
 * @return UVLoop
 */
function uv_loop_new()
{
}

/**
 * Returns the initialized default loop.
 * This function is just a convenient way for having a global loop
 * throughout an application, the default loop is in no way
 * different than the ones initialized with `uv_loop_new()`.
 *
 * @return UVLoop
 */
function uv_default_loop()
{
}

/**
 * This function runs the event loop. It will act differently depending on the
 * specified `$mode`.
 *
 * @param UVLoop $loop
 * @param int $mode
 *  - `UV::RUN_DEFAULT`: Runs the event loop until the reference count drops to
 *    zero. Always returns zero.
 *  - `UV::RUN_ONCE`: Poll for new events once. Note that this function blocks if
 *    there are no pending events. Returns zero when done (no active handles
 *    or requests left), or non-zero if more events are expected (meaning you
 *    should run the event loop again sometime in the future).
 *  - `UV::RUN_NOWAIT`: Poll for new events once but don't block if there are no
 *    pending events.
 */
function uv_run(UVLoop $loop = null, int $mode = UV::RUN_DEFAULT)
{
}

/**
 * start polling.
 *
 * If you want to use a socket. please use `uv_poll_init_socket` instead of this.
 * Windows can't handle socket with this function.
 *
 * @param UVPoll $poll
 * @param int $events UV::READABLE and UV::WRITABLE flags.
 * @param callable $callback expects (UVPoll $poll, int $status, int $events, resource $fd)
 * - the callback `$fd` parameter is the same from `uv_poll_init`.
 */
function uv_poll_start(UVPoll $poll, $events, ?callable $callback = null)
{
}

/**
 * Initialize the poll watcher using a socket descriptor. On unix this is
 * identical to `uv_poll_init`. On windows it takes a `SOCKET` handle.
 *
 * @param UVLoop $loop
 * @param resource $socket
 *
 * @return UVPoll
 */
function uv_poll_init_socket(UVLoop $loop, $socket)
{
}

/**
 * Initialize poll
 *
 * @param UVLoop $loop
 * @param resource $fd PHP `stream`, or `socket`
 *
 * @return UVPoll
 */
function uv_poll_init(UVLoop $loop, $fd)
{
}

/**
 * Stops polling the file descriptor.
 *
 * @param UVPoll $poll
 */
function uv_poll_stop(UVPoll $poll)
{
}

/**
 * close uv handle.
 * Request handle to be closed. `$callback` will be called asynchronously after
 * this call. This MUST be called on each handle before memory is released.
 *
 * Note that handles that wrap file descriptors are closed immediately but
 * `$callback` will still be deferred to the next iteration of the event loop.
 * It gives you a chance to free up any resources associated with the handle.
 *
 * In-progress requests, like uv_connect or uv_write, are cancelled and
 * have their callbacks called asynchronously with status=UV_ECANCELED.
 *
 * @param UV $handle
 * @param callable $callback - expects (UV $handle, int $status)
 */
function uv_close(UV $handle, ?callable $callback = null)
{
}

/**
 * Shutdown the outgoing (write) side of a duplex stream.
 *
 * It waits for pending write requests to complete. The handle should refer to a initialized
 * stream. req should be an uninitialized shutdown request struct. The cb is called after
 * shutdown is complete.
 *
 * @param UVTcp|UVPipe|UVTty $handle
 * @param callable $callback - expects (UVStream $handle, int $status)
 */
function uv_shutdown(UVStream $handle, ?callable $callback = null)
{
}

/**
 * initialize timer handle.
 *
 * @param UVLoop $loop
 *
 * @return UVTimer
 */
function uv_timer_init(UVLoop $loop = null)
{
}

/**
 * Start the timer. `$timeout` and `$repeat` are in milliseconds.
 *
 * If timeout is zero, the callback fires on the next tick of the event loop.
 *
 * If repeat is non-zero, the callback fires first after timeout milliseconds
 * and then repeatedly after repeat milliseconds.
 *
 * @param UVTimer $timer
 * @param float $timeout
 * @param float $repeat
 * @param callable $callback expects (UVTimer $timer, int $status)
 */
function uv_timer_start(UVTimer $timer, float $timeout, float $repeat, callable $callback)
{
}

/**
 * stop specified timer.
 *
 * @param UVTimer $timer
 *
 * @return float
 */
function uv_timer_stop(UVTimer $timer)
{
}

/**
 * Stop the event loop, causing uv_run() to end as soon as possible.
 * This will happen not sooner than the next loop iteration.
 * If this function was called before blocking for i/o,
 * the loop won’t block for i/o on this iteration.
 *
 * @param UVLoop $loop
 */
function uv_stop(UVLoop $loop)
{
}

/**
 * send buffer to specified resource `$handle`.
 *
 * @param UV $handle
 * @param string $data
 * @param callable $callback expects (UV $handle, int $status)
 */
function uv_write(UV $handle, string $data, callable $callback)
{
}

/**
 * Read data from an incoming stream.
 *
 * The `uv_read` callback will be made several times until there is no more data to read
 * or uv_read_stop() is called.
 *
 * @param UVTcp|UVPipe|UVTty $handle
 * @param callable $callback expects (UVStream $handle, $data)
 */
function uv_read_start(UVStream $handle, callable $callback)
{
}

/**
 * open specified file.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param UVLoop $loop
 * @param string $path file path
 * @param string $flag this should be `UV::O_RDONLY `and some constants flag
 * - `UV::O_WRONLY` | `UV::O_CREAT` | `UV::O_APPEND `| `UV::S_IRWXU` | `UV::S_IRUSR`
 * @param int $mode this should be UV::S_IRWXU and some mode flag
 * @param callable $callback expects (resource $stream)
 */
function uv_fs_open(UVLoop $loop, string $path, int $flag, int $mode, callable $callback)
{
}

/**
 * close specified file descriptor.
 *
 * @param UVLoop $loop
 * @param resource $fd PHP `stream`, or `socket`
 * @param callable $callback expects (resource $stream)
 */
function uv_fs_close(UVLoop $loop, $fd, callable $callback)
{
}

/**
 * async read.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop
 * @param resource $fd PHP `stream`, or `socket`
 * @param int $offset
 * @param int $length
 * @param callable $callback - `$callable` expects (resource $stream, $data).
 *
 * `$data` is > 0 if there is data available, 0 if libuv is done reading for
 * now, or < 0 on error.
 *
 * The callee is responsible for closing the `$stream` when an error happens.
 * Trying to read from the `$stream` again is undefined.
 */
function uv_fs_read(UVLoop $loop, $fd, int $offset, int $length, callable $callback)
{
}

/**
 * async write.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop
 * @param resource $fd PHP `stream`, or `socket`
 * @param string $buffer data
 * @param int $offset
 * @param callable $callback expects (resource $stream, int $status)
 */
function uv_fs_write(UVLoop $loop, $fd, string $buffer, int $offset, callable $callback)
{
}

/**
 * async fdatasync.
 * synchronize a file's in-core state with storage device
 *
 * @param UVLoop $loop
 * @param resource $fd
 * @param callable $callback expects (resource $stream, int $status)
 */
function uv_fs_fdatasync(UVLoop $loop, $fd, callable $callback)
{
}

/**
 * async scandir.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop
 * @param string $path
 * @param callable $callback expects (int|array $result_or_dir_contents)
 * @param int $flags
 */
function uv_fs_scandir(UVLoop $loop, string $path, callable $callback, int $flags = 0)
{
}

/**
 * async stat.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop
 * @param string $path
 * @param callable $callback expects (resource $stream, int $stat)
 */
function uv_fs_stat(UVLoop $loop, string $path, callable $callback)
{
}

/**
 * async lstat.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop
 * @param string $path
 * @param callable $callback expects (resource $stream, int $stat)
 */
function uv_fs_lstat(UVLoop $loop, string $path, callable $callback)
{
}

/**
 * async fstat,
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop
 * @param resource $fd
 * @param callable $callback expects (resource $stream, int $stat)
 */
function uv_fs_fstat(UVLoop $loop, $fd, callable $callback)
{
}

/**
 * async fstat.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop
 * @param resource $out_fd
 * @param resource $in_fd
 * @param int $offset
 * @param int $length
 * @param callable $callback expects ($result)
 */
function uv_fs_sendfile(UVLoop $loop, $out_fd, $in_fd, int $offset, int $length, callable $callback)
{
}

/**
 * Returns non-zero if the handle is active, zero if it's inactive.
 *
 * What "active" means depends on the type of handle:
 *
 * - A uv_async handle is always active and cannot be deactivated, except
 *  by closing it with uv_close().
 *
 * - A UVPipe, UVTcp, UVUdp, etc. handle - basically any handle that
 *  deals with I/O - is active when it is doing something that involves I/O,
 *  like reading, writing, connecting, accepting new connections, etc.
 *
 * - A uv_check, uv_idle, uv_timer, etc. handle is active when it has
 *  been started with a call to uv_check_start(), uv_idle_start(), etc.
 *
 * Rule of thumb: if a handle of type uv_foo has a uv_foo_start()
 * function, then it's active from the moment that function is called.
 * Likewise, uv_foo_stop() deactivates the handle again.
 *
 * @param UV $handle
 *
 * @return bool
 */
function uv_is_active(UV $handle)
{
}

/**
 * Start checking the file at `path` for changes every `interval` milliseconds.
 *
 * Your callback is invoked with `status < 0` if `path` does not exist
 * or is inaccessible. The watcher is *not* stopped but your callback is
 * not called again until something changes (e.g. when the file is created
 * or the error reason changes).
 *
 * When `status == 0`, your callback receives pointers to the old and new
 * `uv_stat` structs. They are valid for the duration of the callback
 * only!
 *
 * For maximum portability, use multi-second intervals. Sub-second intervals
 * will not detect all changes on many file systems.
 *
 * @param UVPoll $poll
 * @param callable $callback expects (UVPoll $poll, $status, $old, $new)
 * @param string $path
 */
function uv_fs_poll_start(UVPoll $poll, $callback, string $path, int $interval)
{
}

/**
 * Stop file system polling for changes.
 *
 * @param UVPoll $poll
 */
function uv_fs_poll_stop(UVPoll $poll)
{
}

/**
 * initialize file system poll handle.
 *
 * @param UVLoop $loop
 *
 * @return UVPoll
 */
function uv_fs_poll_init(UVLoop $loop)
{
}

/**
 * returns current exepath. basically this will returns current php path.
 *
 * @return string
 */
function uv_exepath()
{
}

/**
 * returns current working directory.
 *
 * @return string
 */
function uv_cwd()
{
}

/**
 * returns current cpu informations
 *
 * @return array
 */
function uv_cpu_info()
{
}

/**
 * Initialize signal handle.
 *
 * @param UVLoop $loop
 *
 * @return UVSignal
 */
function uv_signal_init(UVLoop $loop = null)
{
}

/**
 * Start the signal handle with the given callback, watching for the given signal.
 *
 * @param UVSignal $handle
 * @param callable $callback expects (UVSignal handle, int signal)
 * @param int $signal
 */
function uv_signal_start(UVSignal $handle, callable $callback, int $signal)
{
}

/**
 * Stop the signal handle, the callback will no longer be called.
 *
 * @param UVSignal $handle
 *
 * @return int
 */
function uv_signal_stop(UVSignal $handle)
{
}

/**
 * Initializes the process handle and starts the process.
 *
 * @param UVLoop $loop
 * @param string $command Program to be executed.
 * @param null|array $args Command line arguments.
 * - On Windows this uses CreateProcess which concatenates the arguments into a string this can
 * cause some strange errors. See the UV_PROCESS_WINDOWS_VERBATIM_ARGUMENTS flag on uv_process_flags.
 * @param null|array $stdio the file descriptors that will be made available to the child process.
 * - The convention is that stdio[0] points to stdin, fd 1 is used for stdout, and fd 2 is stderr.
 * - Note: On Windows file descriptors greater than 2 are available to the child process only if
 * the child processes uses the MSVCRT runtime.
 * @param null|string $cwd Current working directory for the subprocess.
 * @param array $env Environment for the new process. If NULL the parents environment is used.
 * @param null|callable $callback Callback called after the process exits.
 * - Expects (UVProcess $process, $stat, $signal)
 * @param null|int $flags stdio flags
 * - Flags specifying how the stdio container should be passed to the child.
 * @param null|array $options
 *
 * @return UVProcess
 */
function uv_spawn(
    UVLoop $loop,
    string $command,
    array $args,
    array $stdio,
    string $cwd,
    array $env = array(),
    callable $callback,
    int $flags = 0,
    array $options = []
) {
}

/**
 * send signal to specified uv process.
 *
 * @param UVProcess $process
 * @param int $signal
 */
function uv_process_kill(UVProcess $process, int $signal)
{
}

/**
 * Returns process id.
 *
 * @param UVProcess $process
 * @return int
 */
function uv_process_get_pid(UVProcess $process)
{
}

/**
 * send signal to specified pid.
 *
 * @param int $pid process id
 * @param int $signal
 */
function uv_kill(int $pid, int $signal)
{
}

/**
 * Initialize a pipe handle.
 * The ipc argument is a boolean to indicate if this pipe will be used for
 * handle passing between processes (which may change the bytes on the wire).
 *
 * @param UVLoop $loop
 * @param bool $ipc when use for ipc, set `true` otherwise `false`.
 * - Note: needs to be `false` on Windows for proper operations.
 *
 * @return UVPipe
 */
function uv_pipe_init(UVLoop $loop, bool $ipc)
{
}

/**
 * Open an existing file descriptor or HANDLE as a pipe.
 *
 * The file descriptor is set to non-blocking mode.
 *
 * `Note:` The passed file descriptor or HANDLE is not checked for its type,
 * but it’s required that it represents a valid pipe.
 *
 * @param UVPipe $handle
 * @param int|resource $pipe
 *
 * @return int|false
 */
function uv_pipe_open(UVPipe $handle, int $pipe)
{
}

/**
 * Bind the pipe to a file path (Unix) or a name (Windows).
 *
 * @param UVPipe $handle uv pipe handle.
 * @param string $name dunnno. maybe file descriptor.
 *
 * @return int
 */
function uv_pipe_bind(UVPipe $handle, string $name)
{
}

/**
 * Connect to the Unix domain socket or the named pipe.
 *
 * @param UVPipe $handle uv pipe handle.
 * @param string $path named pipe path.
 * @param callable $callback this callback parameter expects (UVPipe $pipe, int $status).
 */
function uv_pipe_connect(UVPipe $handle, string $path, callable $callback)
{
}

/**
 * Set the number of pending pipe instance handles when the pipe server is waiting for connections.
 * Note: This setting applies to Windows only.
 *
 * @param UVPipe $handle
 * @param void $count
 */
function uv_pipe_pending_instances(UVPipe $handle, $count)
{
}

/**
 * @param UV|resource $fd
 * @param integer $flags
 *
 * @return UVStdio
 */
function uv_stdio_new($fd, int $flags)
{
}

/**
 * Initialize the async handle. A NULL callback is allowed.
 * Note: Unlike other handle initialization functions, it immediately starts the handle.
 *
 * @param UVLoop $loop
 * @param callable $callback expects (UVAsync $handle)
 *
 * @return UVAsync
 */
function uv_async_init(UVLoop $loop, callable $callback)
{
}

/**
 * Wake up the event loop and call the async handle’s callback.
 *
 * `Note:` It’s safe to call this function from any thread.
 * The callback will be called on the loop thread.
 *
 * `Note:` uv_async_send() is async-signal-safe.
 * It’s safe to call this function from a signal handler.
 *
 * `Warning:` libuv will coalesce calls to `uv_async_send()`, that is, not every call to it
 * will yield an execution of the callback. For example: if `uv_async_send()` is called
 * 5 times in a row before the callback is called, the callback will only be called once.
 * If `uv_async_send()` is called again after the callback was called, it will be called again.
 *
 * @param UVAsync $handle uv async handle.
 */
function uv_async_send(UVAsync $handle)
{
}

/**
 * Initializes a work request which will run the given `$callback` in a thread from the threadpool.
 * Once `$callback` is completed, `$after_callback` will be called on the loop thread.
 * Executes callbacks in another thread (requires Thread Safe enabled PHP).
 *
 * @param UVLoop $loop
 * @param callable $callback
 * @param callable $after_callback
 */
function uv_queue_work(UVLoop $loop, callable $callback, callable $after_callback)
{
}

/**
 * Initialize the handle.
 *
 * @param UVLoop $loop uv_loop resource.
 *
 * @return UVIdle
 */
function uv_idle_init(UVLoop $loop = null)
{
}

/**
 * Start the handle with the given callback.
 *
 * @param UVIdle $idle uv_idle resource.
 * @param callable $callback expects (UVIdle $handle)
 */
function uv_idle_start(UVIdle $idle, callable $callback)
{
}

/**
 * Stop the handle, the callback will no longer be called.
 *
 * @param UVIdle $idle uv_idle resource.
 */
function uv_idle_stop(UVIdle $idle)
{
}

/**
 * Initialize the handle.
 *
 * @param UVLoop $loop uv loop handle.
 *
 * @return UVPrepare
 */
function uv_prepare_init(UVLoop $loop = null)
{
}

/**
 * Start the handle with the given callback.
 *
 * @param UVPrepare $handle UV handle (prepare)
 * @param callable $callback expects (UVPrepare $prepare, int $status).
 */
function uv_prepare_start(UVPrepare $handle, callable $callback)
{
}

/**
 * Stop the handle, the callback will no longer be called.
 *
 * @param UVPrepare $handle UV handle (prepare).
 */
function uv_prepare_stop(UVPrepare $handle)
{
}

/**
 * Initialize the handle.
 *
 * @param UVLoop $loop uv loop handle
 *
 * @return UVCheck
 */
function uv_check_init(UVLoop $loop = null)
{
}

/**
 * Start the handle with the given callback.
 *
 * The callbacks of idle handles are invoked once per event loop.
 *
 * The idle callback can be used to perform some very low priority activity.
 * For example, you could dispatch a summary of the daily application performance to the
 * developers for analysis during periods of idleness, or use the application’s CPU time
 * to perform SETI calculations :)
 *
 * An idle watcher is also useful in a GUI application.
 *
 * Say you are using an event loop for a file download. If the TCP socket is still being established
 * and no other events are present your event loop will pause (block), which means your progress bar
 * will freeze and the user will face an unresponsive application. In such a case queue up and idle
 * watcher to keep the UI operational.
 *
 * @param UVCheck $handle UV handle (check).
 * @param callable $callback expects (UVCheck $check, int $status).
 */
function uv_check_start(UVCheck $handle, callable $callback)
{
}

/**
 * Stop the handle, the callback will no longer be called.
 *
 * @param UVCheck $handle UV handle (check).
 */
function uv_check_stop(UVCheck $handle)
{
}

/**
 * Get last error code.
 *
 * @param UVLoop|null $uv_loop uv loop handle.
 * @return int
 */
function uv_last_error(UVLoop $uv_loop = null)
{
}

/**
 * Get error code name.
 *
 * @param int $error_code libuv error code.
 * @return string
 */
function uv_err_name(int $error_code)
{
}

/**
 * Get error message.
 *
 * @param int $error_code libuv error code
 * @return string
 */
function uv_strerror(int $error_code)
{
}

/**
 * Update the event loop’s concept of “now”.
 *
 * `Libuv` caches the current time at the start of the event loop tick in order
 * to reduce the number of time-related system calls.
 *
 * You won’t normally need to call this function unless you have callbacks that
 * block the event loop for longer periods of time, where “longer” is somewhat
 * subjective but probably on the order of a millisecond or more.
 *
 * @param UVLoop $uv_loop uv loop handle.
 *
 * @return void
 */
function uv_update_time(UVLoop $uv_loop)
{
}

/**
 * Reference the given handle.
 *
 * References are idempotent, that is, if a handle is already referenced calling
 * this function again will have no effect.
 *
 * `Notes: Reference counting`
 * The libuv event loop (if run in the default mode) will run until there are no active
 *  and referenced handles left. The user can force the loop to exit early by unreferencing
 * handles which are active, for example by calling `uv_unref()` after calling `uv_timer_start()`.
 *
 * A handle can be referenced or unreferenced, the refcounting scheme doesn’t use a counter,
 * so both operations are idempotent.
 *
 * All handles are referenced when active by default, see `uv_is_active()` for a more detailed
 * explanation on what being active involves.
 *
 * @param UV $uv_handle UV.
 *
 * @return void
 */
function uv_ref(UV $uv_handle)
{
}

/**
 * Un-reference the given handle.
 *
 * References are idempotent, that is, if a handle is not referenced calling
 * this function again will have no effect.
 *
 * `Notes: Reference counting`
 * The libuv event loop (if run in the default mode) will run until there are no active
 *  and referenced handles left. The user can force the loop to exit early by unreferencing
 * handles which are active, for example by calling `uv_unref()` after calling `uv_timer_start()`.
 *
 * A handle can be referenced or unreferenced, the refcounting scheme doesn’t use a counter,
 * so both operations are idempotent.
 *
 * All handles are referenced when active by default, see `uv_is_active()` for a more detailed
 * explanation on what being active involves.
 *
 * @param UV $uv_t UV handle.
 *
 * @return void
 */
function uv_unref(UV $uv_t)
{
}

/**
 * Return the current timestamp in milliseconds.
 *
 * The timestamp is cached at the start of the event loop tick,
 * see `uv_update_time()` for details and rationale.
 *
 * The timestamp increases monotonically from some arbitrary point in time.
 * Don’t make assumptions about the starting point, you will only get disappointed.
 *
 * `Note:` Use `uv_hrtime()` if you need sub-millisecond granularity.
 *
 * @return int
 */
function uv_now(UVLoop $uv_loop = null)
{
}

/**
 * Delete specified loop resource.
 *
 * @param UVLoop $uv_loop uv_loop resource.
 *
 * @return void
 */
function uv_loop_delete(UVLoop $uv_loop)
{
}

/**
 * Bind the handle to an address and port.
 *
 * @param UVTcp $uv_tcp uv_tcp resource
 * @param UVSockAddr|resource|int $uv_sockaddr uv sockaddr4 resource.
 *
 * @return void
 */
function uv_tcp_bind(UVTcp $uv_tcp, UVSockAddr $uv_sockaddr)
{
}

/**
 * Bind the handle to an address and port.
 *
 * @param UVTcp $uv_tcp uv_tcp resource
 * @param UVSockAddr|resource|int $uv_sockaddr uv sockaddr6 resource.
 *
 * @return void
 */
function uv_tcp_bind6(UVTcp $uv_tcp, UVSockAddr $uv_sockaddr)
{
}

/**
 * Extended write function for sending handles over a pipe.
 *
 * The pipe must be initialized with ipc == 1.
 *
 * `Note:` $send must be a TCP socket or pipe, which is a server or a connection
 * (listening or connected state). Bound sockets or pipes will be assumed to be servers.
 *
 * @param UVTcp|UVPipe|UVTty $handle
 * @param string $data
 * @param UVTcp|UVPipe $send
 * @param callable $callback expects (UVStream $handle, int $status).
 *
 * @return void
 */
function uv_write2(UVStream $handle, string $data, $send, callable $callback)
{
}

/**
 * Enable TCP_NODELAY, which disables Nagle’s algorithm.
 *
 * @param UVTcp $handle libuv tcp resource.
 * @param bool $enable true means enabled. false means disabled.
 */
function uv_tcp_nodelay(UVTcp $handle, bool $enable)
{
}

/**
 * This call is used in conjunction with `uv_listen()` to accept incoming connections.
 *
 * Call this function after receiving a `uv_connection` to accept the connection.
 * Before calling this function the client handle must be initialized.
 *
 * When the `uv_connection` callback is called it is guaranteed that this function
 * will complete successfully the first time. If you attempt to use it more than once,
 * it may fail. It is suggested to only call this function once per `uv_connection` call.
 *
 * `Note:` server and client must be handles running on the same loop.
 *
 * @param UVTcp|UVPipe $server uv_tcp or uv_pipe server resource.
 * @param UVTcp|UVPipe $client uv_tcp or uv_pipe client resource.
 *
 * @return void
 */
function uv_accept($server, $client)
{
}

/**
 * Start listening for incoming connections.
 *
 * backlog indicates the number of connections the kernel might queue, same as listen(2).
 * When a new incoming connection is received the `uv_connection` callback is called.
 *
 * @param UVTcp|UVPipe $handle UV handle (tcp, udp and pipe).
 * @param int $backlog backlog.
 * @param callable $callback expects ($handle, int $status).
 *
 * @return void
 */
function uv_listen($handle, int $backlog, callable $callback)
{
}

/**
 * Stop reading data from the stream. The `uv_read` callback will no longer be called.
 *
 * This function is idempotent and may be safely called on a stopped stream.
 *
 * @param UVTcp|UVPipe|UVTty $handle UV handle which started uv_read.
 *
 * @return void
 */
function uv_read_stop(UVStream $handle)
{
}

/**
 * Convert a string containing an IPv4 addresses to a binary structure.
 *
 * @param string $ipv4_addr ipv4 address
 * @param int $port port number.
 *
 * @return UVSockAddrIPv4 resource
 */
function uv_ip4_addr(string $ipv4_addr, int $port)
{
}

/**
 * Convert a string containing an IPv6 addresses to a binary structure.
 *
 * @param string $ipv6_addr ipv6 address.
 * @param int $port port number.
 *
 * @return UVSockAddrIPv6 resource
 */
function uv_ip6_addr(string $ipv6_addr, int $port)
{
}

/**
 * Establish an IPv4 TCP connection.
 *
 * Provide an initialized TCP handle and an uninitialized uv_connect. addr
 * should point to an initialized struct sockaddr_in.
 *
 * On Windows if the addr is initialized to point to an unspecified address (0.0.0.0 or ::)
 * it will be changed to point to localhost. This is done to match the behavior of Linux systems.
 *
 * The callback is made when the connection has been established
 * or when a connection error happened.
 *
 * @param UVTcp $handle requires uv_tcp_init() resource.
 * @param UVSockAddr $ipv4_addr requires uv_sockaddr resource.
 * @param callable $callback callable expects (UVTcp $tcp_handle, int $status).
 *
 * @return void
 */
function uv_tcp_connect(UVTcp $handle, UVSockAddr $ipv4_addr, callable $callback)
{
}

/**
 * Establish an IPv6 TCP connection.
 *
 * Provide an initialized TCP handle and an uninitialized uv_connect. addr
 * should point to an initialized struct sockaddr_in6.
 *
 * On Windows if the addr is initialized to point to an unspecified address (0.0.0.0 or ::)
 * it will be changed to point to localhost. This is done to match the behavior of Linux systems.
 *
 * The callback is made when the connection has been established
 * or when a connection error happened.
 *
 * @param UVTcp $handle requires uv_tcp_init() resource.
 * @param UVSockAddrIPv6 $ipv6_addr requires uv_sockaddr resource.
 * @param callable $callback callable expects (UVTcp $tcp_handle, int $status).
 *
 * @return void
 */
function uv_tcp_connect6(UVTcp $handle, UVSockAddrIPv6 $ipv6_addr, callable $callback)
{
}

/**
 * Stop the timer, and if it is repeating restart it using the repeat value as the timeout.
 *
 * @param UVTimer $timer uv_timer resource.
 *
 * @return void
 */
function uv_timer_again(UVTimer $timer)
{
}

/**
 * Set the repeat interval value in milliseconds.
 *
 * The timer will be scheduled to run on the given interval, regardless of
 * the callback execution duration, and will follow normal timer semantics
 * in the case of a time-slice overrun.
 *
 * For example, if a 50ms repeating timer first runs for 17ms, it will be scheduled
 * to run again 33ms later. If other tasks consume more than the 33ms following the
 * first timer callback, then the callback will run as soon as possible.
 *
 * `Note:` If the repeat value is set from a timer callback it does not immediately
 * take effect. If the timer was non-repeating before, it will have been stopped.
 * If it was repeating, then the old repeat value will have been used to schedule
 * the next timeout.

 *
 * @param UVTimer $timer uv_timer resource.
 * @param int $repeat repeat count.
 *
 * @return void
 */
function uv_timer_set_repeat(UVTimer $timer, int $repeat)
{
}

/**
 * Get the timer repeat value.
 *
 * @param UVTimer $timer uv_timer resource.
 *
 * @return int
 */
function uv_timer_get_repeat(UVTimer $timer)
{
}

/**
 * Asynchronous `getaddrinfo(3)`
 *
 * That returns one or more addrinfo structures, each of which contains an Internet address that
 * can be specified in a call to bind(2) or connect(2).
 *
 * The getaddrinfo() function combines the functionality provided by the gethostbyname(3)
 * and getservbyname(3) functions into a single interface.
 *
 * Either $node or $service may be NULL but not both.
 *
 * $hints is a pointer to a struct addrinfo with additional address type constraints, or NULL.
 *
 * Returns 0 on success or an error code < 0 on failure. If successful, the callback will get
 * called sometime in the future with the lookup result, which is either:
 *
 * @param UVLoop $loop
 * @param callable $callback callable expects (array|int $addresses_or_error).
 * @param string $node
 * @param string $service
 * @param array $hints
 *
 * @return void
 */
function uv_getaddrinfo(UVLoop $loop, callable $callback, string $node = null, string $service = null, array $hints = [])
{
}

/**
 * Convert a binary structure containing an IPv4 address to a string.
 *
 * @param UVSockAddr $address
 *
 * @return string
 */
function uv_ip4_name(UVSockAddr $address)
{
}

/**
 * Convert a binary structure containing an IPv6 address to a string.
 *
 * @param UVSockAddr $address
 *
 * @return string
 */
function uv_ip6_name(UVSockAddr $address)
{
}

/**
 * Initialize the handle. No socket is created as of yet.
 *
 * @param UVLoop|null $loop loop resource or null.
 * - if not specified loop resource then use uv_default_loop resource.
 *
 * @return UVTcp UV which initialized for tcp.
 */
function uv_tcp_init(UVLoop $loop = null)
{
}

/**
 * Initialize a new UDP handle. The actual socket is created lazily. Returns 0 on success.
 *
 * @param UVLoop|null $loop loop resource or null.
 * - if not specified loop resource then use uv_default_loop resource.
 *
 * @return UVUdp UV which initialized for udp.
 */
function uv_udp_init(UVLoop $loop = null)
{
}

/**
 * Bind the UDP handle to an IP address and port.
 *
 * - resource – UDP handle. Should have been initialized with uv_udp_init().
 * - address – struct sockaddr_in or struct sockaddr_in6 with the address and port to bind to.
 * - flags – Indicate how the socket will be bound, UV_UDP_IPV6ONLY and UV_UDP_REUSEADDR are supported.
 *
 * @param UVUdp $resource UV handle (udp).
 * @param UVSockAddr $address uv sockaddr(ipv4) resource.
 * @param int $flags unused.
 *
 * @return void
 */
function uv_udp_bind(UVUdp $resource, UVSockAddr $address, int $flags = 0)
{
}

/**
 * Bind the UDP handle to an IP6 address and port.
 *
 * - resource – UDP handle. Should have been initialized with uv_udp_init().
 * - address – struct sockaddr_in6 with the address and port to bind to.
 * - flags – Indicate how the socket will be bound, UV_UDP_IPV6ONLY and UV_UDP_REUSEADDR are supported.
 *
 * @param UVUdp $resource UV handle (udp).
 * @param UVSockAddr $address uv sockaddr(ipv6) resource.
 * @param int $flags Should be 0 or UV::UDP_IPV6ONLY.
 *
 * @return void
 */
function uv_udp_bind6(UVUdp $resource, UVSockAddr $address, int $flags = 0)
{
}

/**
 * Prepare for receiving data.
 *
 * If the socket has not previously been bound with uv_udp_bind() it is bound to 0.0.0.0
 * (the “all interfaces” IPv4 address) and a random port number.
 *
 * - handle – UDP handle. Should have been initialized with uv_udp_init().
 * - callback – Callback to invoke with received data.
 *
 * @param UVUdp $handle UV handle (udp).
 * @param callable $callback callback expects (UVUdp $handle, $data, int $flags).
 *
 * @return void
 */
function uv_udp_recv_start(UVUdp $handle, callable $callback)
{
}

/**
 * Stop listening for incoming datagrams.
 *
 * - handle – UDP handle. Should have been initialized with uv_udp_init().
 *
 * @param UVUdp $handle
 *
 * @return void
 */
function uv_udp_recv_stop(UVUdp $handle)
{
}

/**
 * Set membership for a multicast address
 *
 * - handle – UDP handle. Should have been initialized with uv_udp_init().
 * - multicast_addr – Multicast address to set membership for.
 * - interface_addr – Interface address.
 * - membership – Should be UV_JOIN_GROUP or UV_LEAVE_GROUP.
 *
 * @param UVUdp $handle UV handle (udp).
 * @param string $multicast_addr multicast address.
 * @param string $interface_addr interface address.
 * @param int $membership UV::JOIN_GROUP or UV::LEAVE_GROUP
 *
 * @return int 0 on success, or an error code < 0 on failure.
 */
function uv_udp_set_membership(UVUdp $handle, string $multicast_addr, string $interface_addr, int $membership)
{
}

/**
 * Set IP multicast loop flag.
 *
 * Makes multicast packets loop back to local sockets.
 *
 * - handle – UDP handle. Should have been initialized with uv_udp_init().
 * - on – `true` for on, `false` for off.

 * @param UVUdp $handle UV handle (udp).
 * @param bool $enabled
 *
 * @return void
 */
function uv_udp_set_multicast_loop(UVUdp $handle, bool $enabled)
{
}

/**
 * Set the multicast ttl.
 *
 * - handle – UDP handle. Should have been initialized with uv_udp_init().
 * - ttl – 1 through 255.
 *
 * @param UVUdp $handle UV handle (udp).
 * @param int $ttl multicast ttl.
 *
 * @return void
 */
function uv_udp_set_multicast_ttl(UVUdp $handle, int $ttl)
{
}

/**
 * Set broadcast on or off.
 *
 * - handle – UDP handle. Should have been initialized with uv_udp_init().
 * - on – 1 for on, 0 for off.
 *
 * @param UVUdp $handle UV handle (udp).
 * @param bool $enabled
 *
 * @return void
 */
function uv_udp_set_broadcast(UVUdp $handle, bool $enabled)
{
}

/**
 * Send data over the UDP socket.
 *
 * If the socket has not previously been bound with uv_udp_bind() it will be bound to 0.0.0.0
 * (the “all interfaces” IPv4 address) and a random port number.
 *
 * On Windows if the addr is initialized to point to an unspecified address (0.0.0.0 or ::)
 * it will be changed to point to localhost. This is done to match the behavior of Linux systems.
 *
 * - handle – UDP handle. Should have been initialized with uv_udp_init().
 * - data – to send.
 * - uv_addr – struct sockaddr_in or struct sockaddr_in6 with the address and port of the remote peer.
 * - callback – Callback to invoke when the data has been sent out.
 *
 * @param UVUdp $handle UV handle (udp).
 * @param string $data data.
 * @param UVSockAddr $uv_addr uv_ip4_addr.
 * @param callable $callback callback expects (UVUdp $handle, int $status).
 *
 * @return void
 */
function uv_udp_send(UVUdp $handle, string $data, UVSockAddr $uv_addr, callable $callback)
{
}

/**
 * Send data over the UDP socket.
 *
 * If the socket has not previously been bound with uv_udp_bind() it will be bound to 0.0.0.0
 * (the “all interfaces” IPv6 address) and a random port number.
 *
 * On Windows if the addr is initialized to point to an unspecified address (0.0.0.0 or ::)
 * it will be changed to point to localhost. This is done to match the behavior of Linux systems.
 *
 * - handle – UDP handle. Should have been initialized with uv_udp_init().
 * - data – to send.
 * - uv_addr – struct sockaddr_in6 with the address and port of the remote peer.
 * - callback – Callback to invoke when the data has been sent out.
 *
 * @param UVUdp $handle UV handle (udp).
 * @param string $data data.
 * @param UVSockAddrIPv6 $uv_addr6 uv_ip6_addr.
 * @param callable $callback callback expects (UVUdp $handle, int $status).
 *
 * @return void
 */
function uv_udp_send6(UVUdp $handle, string $data, UVSockAddrIPv6 $uv_addr6, callable $callback)
{
}

/**
 * Returns 1 if the stream is readable, 0 otherwise.
 *
 * @param UVTcp|UVPipe|UVTty $handle
 *
 * @return bool
 */
function uv_is_readable(UVStream $handle)
{
}

/**
 * Returns 1 if the stream is writable, 0 otherwise.
 *
 * @param UVTcp|UVPipe|UVTty $handle
 *
 * @return bool
 */
function uv_is_writable(UVStream $handle)
{
}

/**
 * Walk the list of handles: callable will be executed with the given arg.
 *
 * @param UVLoop $loop
 * @param callable $closure
 * @param array|null $opaque
 *
 * @return bool
 */
function uv_walk(UVLoop $loop, callable $closure, array $opaque = null)
{
}

/**
 * Used to detect what type of stream should be used with a given file descriptor.
 *
 * Usually this will be used during initialization to guess the type of the stdio streams.
 *
 * @param resource $uv
 *
 * @return int
 */
function uv_guess_handle($uv)
{
}

/**
 * Gets the load average. @see: https://en.wikipedia.org/wiki/Load_(computing)
 *
 * Note: returns [0,0,0] on Windows (i.e., it’s not implemented).
 *
 * @return array
 */
function uv_loadavg()
{
}

/**
 * Initialize rwlock resource.
 *
 * @return UVLock returns uv rwlock resource.
 */
function uv_rwlock_init()
{
}

/**
 * Set read lock.
 *
 * @param UVLock $handle UV handle (uv rwlock).
 */
function uv_rwlock_rdlock(UVLock $handle)
{
}

/**
 * @param UVLock $handle
 *
 * @return bool
 */
function uv_rwlock_tryrdlock(UVLock $handle)
{
}

/**
 * Unlock read lock.
 *
 * @param UVLock $handle UV handle (uv rwlock)
 *
 * @return void
 */
function uv_rwlock_rdunlock(UVLock $handle)
{
}

/**
 * Set write lock.
 *
 * @param UVLock $handle UV handle (uv rwlock).
 *
 * @return void
 */
function uv_rwlock_wrlock(UVLock $handle)
{
}

/**
 * @param UVLock $handle
 */
function uv_rwlock_trywrlock(UVLock $handle)
{
}

/**
 * Unlock write lock.
 *
 * @param UVLock $handle UV handle (uv rwlock).
 */
function uv_rwlock_wrunlock(UVLock $handle)
{
}

/**
 * Initialize mutex resource.
 *
 * @return UVLock uv mutex resource
 */
function uv_mutex_init()
{
}

/**
 * Lock mutex.
 *
 * @param UVLock $lock UV handle (uv mutex).
 *
 * @return void
 */
function uv_mutex_lock(UVLock $lock)
{
}

/**
 * @param UVLock $lock
 *
 * @return bool
 */
function uv_mutex_trylock(UVLock $lock)
{
}

/**
 * Initialize semaphore resource.
 *
 * @param int $value
 * @return UVLock
 */
function uv_sem_init(int $value)
{
}

/**
 * Post semaphore.
 *
 * @param UVLock $sem UV handle (uv sem).
 *
 * @return void
 */
function uv_sem_post(UVLock $sem)
{
}

/**
 * @param UVLock $sem
 *
 * @return void
 */
function uv_sem_wait(UVLock $sem)
{
}

/**
 * @param UVLock $sem
 *
 * @return void
 */
function uv_sem_trywait(UVLock $sem)
{
}

/**
 * Returns the current high-resolution real time.
 *
 * This is expressed in nanoseconds. It is relative to an arbitrary time in the past.
 * It is not related to the time of day and therefore not subject to clock drift.
 * The primary use is for measuring performance between intervals.
 *
 * `Note:` Not every platform can support nanosecond resolution; however,
 * this value will always be in nanoseconds.
 *
 * @return int
 */
function uv_hrtime()
{
}

/**
 * Async fsync.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle.
 * @param resource $fd
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_fsync(UVLoop $loop, $fd, callable $callback)
{
}

/**
 * Async ftruncate.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle.
 * @param resource $fd
 * @param int $offset
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_ftruncate(UVLoop $loop, $fd, int $offset, callable $callback)
{
}

/**
 * Async mkdir.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle
 * @param string $path
 * @param int $mode
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_mkdir(UVLoop $loop, string $path, int $mode, callable $callback)
{
}

/**
 * Async rmdir.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle
 * @param string $path
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_rmdir(UVLoop $loop, string $path, callable $callback)
{
}

/**
 * Async unlink.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle
 * @param string $path
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_unlink(UVLoop $loop, string $path, callable $callback)
{
}

/**
 * Async rename.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle.
 * @param string $from
 * @param string $to
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_rename(UVLoop $loop, string $from, string $to, callable $callback)
{
}

/**
 * Async utime.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle.
 * @param string $path
 * @param int $utime
 * @param int $atime
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_utime(UVLoop $loop, string $path, int $utime, int $atime, callable $callback)
{
}

/**
 * Async futime.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle.
 * @param resource $fd
 * @param int $utime
 * @param int $atime
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_futime(UVLoop $loop, $fd, int $utime, int $atime, callable $callback)
{
}

/**
 * Async chmod.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle.
 * @param string $path
 * @param int $mode
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_chmod(UVLoop $loop, string $path, int $mode, callable $callback)
{
}

/**
 * Async fchmod.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle.
 * @param resource $fd
 * @param int $mode
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_fchmod(UVLoop $loop, $fd, int $mode, callable $callback)
{
}

/**
 * Async chown.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle.
 * @param string $path
 * @param int $uid
 * @param int $gid
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_chown(UVLoop $loop, string $path, int $uid, int $gid, callable $callback)
{
}

/**
 * Async fchown.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle.
 * @param resource $fd
 * @param int $uid
 * @param int $gid
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_fchown(UVLoop $loop, $fd, int $uid, int $gid, callable $callback)
{
}

/**
 * Async link.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle.
 * @param string $from
 * @param string $to
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_link(UVLoop $loop, string $from, string $to, callable $callback)
{
}

/**
 * Async symlink.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle.
 * @param string $from
 * @param string $to
 * @param int $flags
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_symlink(UVLoop $loop, string $from, string $to, int $flags, callable $callback)
{
}

/**
 * Async readlink.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop uv loop handle
 * @param string $path
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_readlink(UVLoop $loop, string $path, callable $callback)
{
}

/**
 * Async readdir.
 * Executes a blocking system call asynchronously (in a thread pool) and call the specified callback in
 * the specified loop after completion.
 *
 * @param UVLoop $loop  uv loop handle
 * @param string $path
 * @param int $flags
 * @param callable $callback callback expects (resource $fd, int $result).
 *
 * @return void
 */
function uv_fs_readdir(UVLoop $loop, string $path, int $flags, callable $callback)
{
}

/**
 * Initialize fs event.
 *
 * @param UVLoop $loop uv loop handle
 * @param string $path
 * @param callable $callback callback expects (resource $fd, int $result).
 * @param int $flags
 *
 * @return resource
 */
function uv_fs_event_init(UVLoop $loop, string $path, callable $callback, int $flags = 0)
{
}

/**
 * Initialize a new TTY stream with the given file descriptor.
 *
 * Usually the file descriptor will be:
 *  0 = stdin
 *  1 = stdout
 *  2 = stderr
 *
 * On Unix this function will determine the path of the fd of the terminal using ttyname_r(3),
 * open it, and use it if the passed file descriptor refers to a TTY. This lets libuv put the
 * tty in non-blocking mode without affecting other processes that share the tty.
 *
 * This function is not thread safe on systems that don’t support ioctl TIOCGPTN or TIOCPTYGNAME,
 * for instance OpenBSD and Solaris.
 *
 * `Note:` If reopening the TTY fails, `libuv` falls back to blocking writes.
 *
 * @param UVLoop $loop uv loop handle.
 * @param resource $fd
 * @param int $readable
 *
 * @return UVTty
 */
function uv_tty_init(UVLoop $loop, $fd, int $readable)
{
}

/**
 * Gets the current Window size. On success it returns 0.
 *
 * @param UVTty $tty
 * @param int $width
 * @param int $height
 *
 * @return int
 */
function uv_tty_get_winsize(UVTty $tty, int &$width, int &$height)
{
}

/**
 * Set the TTY using the specified terminal mode.
 *
 * @param UVTty $tty
 * @param int $mode
 *
 * @return int
 */
function uv_tty_set_mode(UVTty $tty, int $mode)
{
}

/**
 * To be called when the program exits.
 *
 * Resets TTY settings to default values for the next process to take over.
 *
 * This function is async signal-safe on Unix platforms but can fail with error code
 * UV_EBUSY if you call it when execution is inside uv_tty_set_mode().
 *
 * @return void
 */
function uv_tty_reset_mode()
{
}

/**
 * Gets the current system uptime.
 *
 * @return float
 */
function uv_uptime()
{
}

/**
 * Returns current free memory size.
 *
 * @return int
 */
function uv_get_free_memory()
{
}

/**
 * Gets memory information (in bytes).
 *
 * @return int
 */
function uv_get_total_memory()
{
}

/**
 * Gets address information about the network interfaces on the system.
 *
 * An array of count elements is allocated and returned in addresses.
 * It must be freed by the user, calling uv_free_interface_addresses().
 *
 * @return array
 */
function uv_interface_addresses()
{
}

/**
 * Change working directory.
 *
 * @param string $directory
 * @return bool
 */
function uv_chdir(string $directory)
{
}

/**
 * Get the current address to which the handle is bound.
 *
 * Name must point to a valid and big enough chunk of memory,
 * struct sockaddr_storage is recommended for IPv4 and IPv6 support.
 *
 * @param UVTcp $uv_sock
 *
 * @return string
 */
function uv_tcp_getsockname(UVTcp $uv_sock)
{
}

/**
 * Get the address of the peer connected to the handle.
 *
 * Name must point to a valid and big enough chunk of memory,
 * struct sockaddr_storage is recommended for IPv4 and IPv6 support.
 *
 * @param UVTcp $uv_sock
 *
 * @return string
 */
function uv_tcp_getpeername(UVTcp $uv_sock)
{
}

/**
 * Get the local IP and port of the UDP handle.
 *
 * @param UVUdp $uv_sockaddr
 *
 * @return string
 */
function uv_udp_getsockname(UVUdp $uv_sock)
{
}

/**
 * Gets the resident set size (RSS) for the current process.
 *
 * @return int
 */
function uv_resident_set_memory()
{
}

/**
 * Returns UV handle type.
 *
 * @param UV $uv uv_handle.
 *
 * @return int
 * The kind of the `libuv` handle.
 * - UV_UNKNOWN_HANDLE = 0;
 * - UV_ASYNC = 1;
 * - UV_CHECK = 2;
 * - UV_FS_EVENT = 3;
 * - UV_FS_POLL = 4;
 * - UV_HANDLE = 5;
 * - UV_IDLE = 6;
 * - UV_NAMED_PIPE = 7;
 * - UV_POLL = 8;
 * - UV_PREPARE = 9;
 * - UV_PROCESS = 10;
 * - UV_STREAM = 11;
 * - UV_TCP = 12;
 * - UV_TIMER = 13;
 * - UV_TTY = 14;
 * - UV_UDP = 15;
 * - UV_SIGNAL = 16;
 * - UV_FILE = 17;
 * - UV_HANDLE_TYPE_MAX = 18;
 */
function uv_handle_get_type(UV $uv)
{
}

/**
 * Open an existing file descriptor or SOCKET as a TCP handle.
 *
 * The file descriptor is set to non-blocking mode.
 *
 * `Note:` The passed file descriptor or SOCKET is not checked for its type,
 * but it’s required that it represents a valid stream socket.
 *
 * @param UVTcp $handle
 * @param int|resource $tcpfd
 *
 * @return int|false
 */
function uv_tcp_open(UVTcp $handle, int $tcpfd)
{
}

/**
 * Opens an existing file descriptor or Windows SOCKET as a UDP handle.
 *
 * The file descriptor is set to non-blocking mode.
 *
 * `Unix only:` The only requirement of the sock argument is that it follows
 * the datagram contract (works in unconnected mode, supports sendmsg()/recvmsg(), etc).
 * In other words, other datagram-type sockets like raw sockets or netlink sockets
 * can also be passed to this function.
 *
 * `Note:` The passed file descriptor or SOCKET is not checked for its type,
 * but it’s required that it represents a valid datagram socket..
 *
 * @param UVUdp $handle
 * @param int|resource $udpfd
 *
 * @return int|false
 */
function uv_udp_open(UVUdp $handle, int $udpfd)
{
}

////////////////////////
// Not part of `libuv`
////////////////////////

/**
 * @param UVLoop|null $uv_loop
 *
 * @return void
 */
function uv_run_once(UVLoop $uv_loop = null)
{
}

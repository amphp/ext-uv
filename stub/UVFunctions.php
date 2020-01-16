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
 * It may return NULL in case of allocation failure. This function is just a convenient
 * way for having a global loop throughout an application, the default loop is in no way
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
 * If you want to use a socket. please use uv_poll_init_socket instead of this. Windows can't handle socket with this function.
 *
 * @param UVPoll $poll
 * @param int $events UV::READABLE and UV::WRITABLE flags.
 * @param callable $callback expects (UVPoll $poll, int $status, int $events, mixed $connection)
 * - the connection parameter passes uv_poll_init `$fd`.
 */
function uv_poll_start(UVPoll $poll, $events, ?callable $callback = null)
{
}

/**
 * Initialize the poll watcher using a socket descriptor. On unix this is
 * identical to uv_poll_init. On windows it takes a SOCKET handle.
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
 * In-progress requests, like uv_connect_t or uv_write_t, are cancelled and
 * have their callbacks called asynchronously with status=UV_ECANCELED.
 *
 * @param UVHandle $handle
 * @param callable $callback - expects (UVHandle $handle, int $status)
 */
function uv_close(UVHandle $handle, ?callable $callback = null)
{
}

/**
 * shutdown uv handle.
 *
 * @param UVHandle $handle
 * @param callable $callback - expects (UVHandle $handle, int $status)
 */
function uv_shutdown(UVHandle $handle, ?callable $callback = null)
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
 * @param callable $callback expects (UVTimer $timer, int$status)
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
 * @param UVHandle $handle
 * @param string $data
 * @param callable $callback expects (UVHandle $handle, int $status)
 */
function uv_write(UVHandle $handle, string $data, callable $callback)
{
}

/**
 * starts read callback for uv resources `$handle`.
 *
 * @param UVHandle $handle
 * @param callable $callback expects (UVHandle $handle, int $read, string buffer)
 */
function uv_read_start(UVHandle $handle, callable $callback)
{
}

/**
 * open specified file,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
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
 * async read,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param UVLoop $loop
 * @param resource $fd PHP `stream`, or `socket`
 * @param int $offset
 * @param int $length
 * @param callable $callback - `$callable` expects (resource $stream, int $read, string $buffer).
 *
 * `$read` is > 0 if there is data available, 0 if libuv is done reading for
 * now, or < 0 on error.
 *
 * The callee is responsible for closing the `$stream` when an error happens.
 * Trying to read from the `$stream` again is undefined.
 *
 * The callee is responsible for freeing the `$buffer`, libuv does not reuse it.
 * The `$buffer` may be a null `$buffer` (where buf->base=NULL and buf->len=0) on
 * EOF or error.
 */
function uv_fs_read(UVLoop $loop, $fd, int $offset, int $length, callable $callback)
{
}

/**
 * async write,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
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
 * async stat,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param UVLoop $loop
 * @param string $path
 * @param callable $callback expects (resource $stream, int $stat)
 */
function uv_fs_stat(UVLoop $loop, string $path, callable $callback)
{
}

/**
 * async lstat,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
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
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param UVLoop $loop
 * @param resource $fd
 * @param callable $callback expects (resource $stream, int $stat)
 */
function uv_fs_fstat(UVLoop $loop, $fd, callable $callback)
{
}

/**
 * async fstat,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
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
 * - A uv_async_t handle is always active and cannot be deactivated, except
 *  by closing it with uv_close().
 *
 * - A UVPipe_t, UVTcp_t, UVUdp_t, etc. handle - basically any handle that
 *  deals with I/O - is active when it is doing something that involves I/O,
 *  like reading, writing, connecting, accepting new connections, etc.
 *
 * - A uv_check_t, uv_idle_t, uv_timer_t, etc. handle is active when it has
 *  been started with a call to uv_check_start(), uv_idle_start(), etc.
 *
 * Rule of thumb: if a handle of type uv_foo_t has a uv_foo_start()
 * function, then it's active from the moment that function is called.
 * Likewise, uv_foo_stop() deactivates the handle again.
 *
 * @param UVHandle $handle
 *
 * @return bool
 */
function uv_is_active(UVHandle $handle)
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
 * `uv_stat_t` structs. They are valid for the duration of the callback
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
    int $flags,
    array $options
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
 * The file descriptor is set to non-blocking mode.
 *
 * `Note:` The passed file descriptor or HANDLE is not checked for its type,
 * but it’s required that it represents a valid pipe.
 *
 * @param UVPipe $handle
 * @param int $pipe dunnno. maybe file descriptor.
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
 * @param UVHandle $fd
 * @param integer $flags
 *
 * @return UVStdio
 */
function uv_stdio_new(UVHandle $fd, int $flags)
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
 * Execute callbacks in another thread (requires Thread Safe enabled PHP).
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
 * @param UVPrepare $handle uv resource handle (prepare)
 * @param callable $callback expects (UVPrepare $prepare, int $status).
 */
function uv_prepare_start(UVPrepare $handle, callable $callback)
{
}

/**
 * Stop the handle, the callback will no longer be called.
 *
 * @param UVPrepare $handle uv resource handle (prepare).
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
 * @param UVCheck $handle uv resource handle (check).
 * @param callable $callback expects (UVCheck $check, int $status).
 */
function uv_check_start(UVCheck $handle, callable $callback)
{
}

/**
 * Stop the handle, the callback will no longer be called.
 *
 * @param UVCheck $handle uv resource handle (check).
 */
function uv_check_stop(UVCheck $handle)
{
}

// from https://github.com/JetBrains/phpstorm-stubs/blob/master/uv/uv_functions.php

/**
 * Decrement reference.
 *
 * @param resource $uv_t resource handle.
 *
 * @return void
 */
function uv_unref($uv_t)
{
}

/**
 * Get last error code.
 *
 * @param UVLoop|null $uv_loop uv loop handle.
 * @return int
 */
function uv_last_error($uv_loop = null)
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
 * @param UVLoop $uv_loop uv loop handle.
 *
 * @return void
 */
function uv_update_time($uv_loop)
{
}

/**
 * Increment reference count.
 *
 * @param UVHandle $uv_handle uv resource.
 *
 * @return void
 */
function uv_ref(UVHandle $uv_handle)
{
}

/**
 * @param UVLoop|null $uv_loop
 *
 * @return void
 */
function uv_run_once(UVLoop $uv_loop = null)
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
 * @return int
 */
function uv_now()
{
}

/**
 * Binds a name to a socket.
 *
 * @param UVTcp $uv_tcp uv_tcp resource
 * @param resource $uv_sockaddr uv sockaddr4 resource.
 *
 * @return void
 */
function uv_tcp_bind(UVTcp $uv_tcp, $uv_sockaddr)
{
}

/**
 * Binds a name to a socket.
 *
 * @param UVTcp $uv_tcp uv_tcp resource
 * @param resource $uv_sockaddr uv sockaddr6 resource.
 *
 * @return void
 */
function uv_tcp_bind6(UVTcp $uv_tcp, $uv_sockaddr)
{
}

/**
 * @param UVHandle $handle
 * @param string $data
 * @param resource $send
 * @param callable $callback
 *
 * @return void
 */
function uv_write2(UVHandle $handle, string $data, $send, callable $callback)
{
}

/**
 * Set Nagel's flags for specified tcp resource.
 *
 * @param resource $handle libuv tcp resource.
 * @param bool $enable true means enabled. false means disabled.
 */
function uv_tcp_nodelay($handle, bool $enable)
{
}

/**
 * Accepts a connection on a socket.
 *
 * @param resource $server uv_tcp or uv_pipe server resource.
 * @param resource $client uv_tcp or uv_pipe client resource.
 *
 * @return void
 */
function uv_accept($server, $client)
{
}

/**
 * @param resource $handle
 * @param callable $callback
 *
 * @return void
 */
function uv_read2_start($handle, callable $callback)
{
}

/**
 * Stop read callback.
 *
 * @param resource $handle uv resource handle which started uv_read.
 *
 * @return void
 */
function uv_read_stop($handle)
{
}

/**
 * Create a ipv4 sockaddr.
 *
 * @param string $ipv4_addr ipv4 address
 * @param int $port port number.
 *
 * @return resource
 */
function uv_ip4_addr(string $ipv4_addr, int $port)
{
}

/**
 * Create a ipv6 sockaddr.
 *
 * @param string $ipv6_addr ipv6 address.
 * @param int $port port number.
 *
 * @return resource
 */
function uv_ip6_addr(string $ipv6_addr, int $port)
{
}

/**
 * Listens for a connection on a uv handle.
 *
 * @param resource $handle uv resource handle (tcp, udp and pipe).
 * @param int $backlog backlog.
 * @param callable $callback this callback parameter expects (resource $connection, long $status).
 *
 * @return void
 */
function uv_listen($handle, int $backlog, callable $callback)
{
}

/**
 * Connect to specified ip address and port.
 *
 * @param resource $handle requires uv_tcp_init() resource.
 * @param resource $ipv4_addr requires uv_sockaddr resource.
 * @param callable $callback callable variables. This callback expects (resource $tcp_handle, $status).
 *
 * @return void
 */
function uv_tcp_connect($handle, $ipv4_addr, callable $callback)
{
}

/**
 * Connect to specified ip address and port.
 *
 * @param resource $handle requires uv_tcp_init() resource.
 * @param resource $ipv6_addr requires uv_sockaddr resource.
 * @param callable $callback callable variables. This callback expects (resource $tcp_handle, $status).
 *
 * @return void
 */
function uv_tcp_connect6($handle, $ipv6_addr, callable $callback)
{
}

/**
 * Restart timer.
 *
 * @param resource $timer uv_timer resource.
 *
 * @return void
 */
function uv_timer_again($timer)
{
}

/**
 * Set repeat count.
 *
 * @param resource $timer uv_timer resource.
 * @param int $repeat repeat count.
 *
 * @return void
 */
function uv_timer_set_repeat($timer, int $repeat)
{
}

/**
 * Returns repeat interval.
 *
 * @param resource $timer uv_timer resource.
 *
 * @return int
 */
function uv_timer_get_repeat($timer)
{
}

/**
 * @param UVLoop $loop
 * @param callable $callback
 * @param string $node
 * @param string $service
 * @param array $hints
 *
 * @return void
 */
function uv_getaddrinfo(UVLoop $loop, callable $callback, string $node, string $service, array $hints)
{
}

/**
 * Create a tcp socket.
 *
 * @param resource|null $loop loop resource or null. if not specified loop resource then use uv_default_loop resource.
 *
 * @return resource uv resource which initialized for tcp.
 */
function uv_tcp_init($loop = null)
{
}

/**
 * Create a udp socket.
 *
 * @param resource|null $loop loop resource or null. if not specified loop resource then use uv_default_loop resource.
 *
 * @return resource uv resource which initialized for udp.
 */
function uv_udp_init($loop = null)
{
}

/**
 * Listens for a connection on a uv udp handle.
 *
 * @param resource $resource uv resource handle (udp).
 * @param resource $address uv sockaddr(ipv4) resource.
 * @param int $flags unused.
 *
 * @return void
 */
function uv_udp_bind($resource, $address, int $flags)
{
}

/**
 * Listens for a connection on a uv udp handle.
 *
 * @param resource $resource uv resource handle (udp).
 * @param resource $address uv sockaddr(ipv6) resource.
 * @param int $flags Should be 0 or UV::UDP_IPV6ONLY.
 *
 * @return void
 */
function uv_udp_bind6($resource, $address, int $flags)
{
}

/**
 * Start receive callback.
 *
 * @param resource $handle uv resource handle (udp).
 * @param callable $callback this callback parameter expects (resource $stream, long $nread, string $buffer)..
 *
 * @return void
 */
function uv_udp_recv_start($handle, callable $callback)
{
}

/**
 * Stop receive callback.
 *
 * @param resource $handle
 *
 * @return void
 */
function uv_udp_recv_stop($handle)
{
}

/**
 * Join or leave udp muticast group.
 *
 * @param resource $handle uv resource handle (udp).
 * @param string $multicast_addr multicast address.
 * @param string $interface_addr interface address.
 * @param int $membership UV::JOIN_GROUP or UV::LEAVE_GROUP
 *
 * @return int
 */
function uv_udp_set_membership($handle, string $multicast_addr, string $interface_addr, int $membership)
{
}

/**
 * Set multicast loop.
 *
 * @param resource $handle uv resource handle (udp).
 * @param int $enabled
 *
 * @return void
 */
function uv_udp_set_multicast_loop($handle, int $enabled)
{
}

/**
 * Set multicast ttl.
 *
 * @param resource $handle uv resource handle (udp).
 * @param int $ttl multicast ttl.
 *
 * @return void
 */
function uv_udp_set_multicast_ttl($handle, int $ttl)
{
}

/**
 * Set udp broadcast.
 *
 * @param resource $handle uv resource handle (udp).
 * @param bool $enabled
 *
 * @return void
 */
function uv_udp_set_broadcast($handle, bool $enabled)
{
}

/**
 * Send buffer to specified address.
 *
 * @param resource $handle uv resource handle (udp).
 * @param string $data data.
 * @param resource $uv_addr uv_ip4_addr.
 * @param callable $callback this callback parameter expects (resource $stream, long $status).
 *
 * @return void
 */
function uv_udp_send($handle, string $data, $uv_addr, callable $callback)
{
}

/**
 * Send buffer to specified address.
 *
 * @param resource $handle uv resource handle (udp).
 * @param string $data data.
 * @param resource $uv_addr6 uv_ip6_addr.
 * @param callable $callback this callback parameter expects (resource $stream, long $status).
 *
 * @return void
 */
function uv_udp_send6($handle, string $data, $uv_addr6, callable $callback)
{
}

/**
 * @param resource $handle
 *
 * @return bool
 */
function uv_is_readable($handle)
{
}

/**
 * @param resource $handle
 *
 * @return bool
 */
function uv_is_writable($handle)
{
}

/**
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
 * @param resource $uv
 *
 * @return int
 */
function uv_guess_handle($uv)
{
}

/**
 * Returns current uv type. (this is not libuv function. util for php-uv).
 *
 * @param resource $uv uv_handle.
 *
 * @return int  should return UV::IS_UV_* constatns. e.g) UV::IS_UV_TCP.
 */
function uv_handle_type($uv)
{
}

/**
 * @param UVLoop $loop
 * @param array $options
 * @param int $optmask
 *
 * @return resource
 */
function uv_ares_init_options(UVLoop $loop, array $options, int $optmask)
{
}

/**
 * @param resource $handle
 * @param string $name
 * @param int $flag
 * @param callable $callback
 *
 * @return void
 */
function ares_gethostbyname($handle, string $name, int $flag, callable $callback)
{
}

/**
 * Returns current loadaverage.
 *
 * Note: returns array on windows box. (does not support load average on windows).
 *
 * @return array
 */
function uv_loadavg()
{
}

/**
 * Returns current uptime.
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
 * Returns total memory size.
 *
 * @return int
 */
function uv_get_total_memory()
{
}

/**
 * @return int
 */
function uv_hrtime()
{
}

/**
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
 * Initialize rwlock resource.
 *
 * @return resource returns uv rwlock resource.
 */
function uv_rwlock_init()
{
}

/**
 * Set read lock.
 *
 * @param resource $handle uv resource handle (uv rwlock).
 */
function uv_rwlock_rdlock($handle)
{
}

/**
 * @param resource $handle
 *
 * @return bool
 */
function uv_rwlock_tryrdlock($handle)
{
}

/**
 * Unlock read lock.
 *
 * @param resource $handle uv resource handle (uv rwlock)
 *
 * @return void
 */
function uv_rwlock_rdunlock($handle)
{
}

/**
 * Set write lock.
 *
 * @param resource $handle uv resource handle (uv rwlock).
 *
 * @return void
 */
function uv_rwlock_wrlock($handle)
{
}

/**
 * @param resource $handle
 */
function uv_rwlock_trywrlock($handle)
{
}

/**
 * Unlock write lock.
 *
 * @param resource $handle uv resource handle (uv rwlock).
 */
function uv_rwlock_wrunlock($handle)
{
}

/**
 * Initialize mutex resource.
 *
 * @return resource uv mutex resource
 */
function uv_mutex_init()
{
}

/**
 * Lock mutex.
 *
 * @param resource $lock uv resource handle (uv mutex).
 *
 * @return void
 */
function uv_mutex_lock($lock)
{
}

/**
 * @param resource $lock
 *
 * @return bool
 */
function uv_mutex_trylock($lock)
{
}

/**
 * Initialize semaphore resource.
 *
 * @param int $value
 * @return resource
 */
function uv_sem_init(int $value)
{
}

/**
 * Post semaphore.
 *
 * @param resource $sem uv resource handle (uv sem).
 *
 * @return void
 */
function uv_sem_post($sem)
{
}

/**
 * @param resource $sem
 *
 * @return void
 */
function uv_sem_wait($sem)
{
}

/**
 * @param resource $sem
 *
 * @return void
 */
function uv_sem_trywait($sem)
{
}

/**
 * Async fsync.
 *
 * @param UVLoop $loop uv loop handle.
 * @param resource $fd
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_fsync(UVLoop $loop, $fd, callable $callback)
{
}

/**
 * Async ftruncate.
 *
 * @param UVLoop $loop uv loop handle.
 * @param resource $fd
 * @param int $offset
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_ftruncate(UVLoop $loop, $fd, int $offset, callable $callback)
{
}

/**
 * Async mkdir.
 *
 * @param UVLoop $loop uv loop handle
 * @param string $path
 * @param int $mode
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_mkdir(UVLoop $loop, string $path, int $mode, callable $callback)
{
}

/**
 * Async rmdir.
 *
 * @param UVLoop $loop uv loop handle
 * @param string $path
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_rmdir(UVLoop $loop, string $path, callable $callback)
{
}

/**
 * Async unlink.
 *
 * @param UVLoop $loop uv loop handle
 * @param string $path
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_unlink(UVLoop $loop, string $path, callable $callback)
{
}

/**
 * Async rename.
 *
 * @param UVLoop $loop uv loop handle.
 * @param string $from
 * @param string $to
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_rename(UVLoop $loop, string $from, string $to, callable $callback)
{
}

/**
 * Async utime.
 *
 * @param UVLoop $loop uv loop handle.
 * @param string $path
 * @param int $utime
 * @param int $atime
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_utime(UVLoop $loop, string $path, int $utime, int $atime, callable $callback)
{
}

/**
 * Async futime.
 *
 * @param UVLoop $loop uv loop handle.
 * @param resource $fd
 * @param int $utime
 * @param int $atime
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_futime(UVLoop $loop, $fd, int $utime, int $atime, callable $callback)
{
}

/**
 * Async chmod.
 *
 * @param UVLoop $loop uv loop handle.
 * @param string $path
 * @param int $mode
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_chmod(UVLoop $loop, string $path, int $mode, callable $callback)
{
}

/**
 * Async fchmod.
 *
 * @param UVLoop $loop uv loop handle.
 * @param resource $fd
 * @param int $mode
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_fchmod(UVLoop $loop, $fd, int $mode, callable $callback)
{
}

/**
 * Async chown.
 *
 * @param UVLoop $loop uv loop handle.
 * @param string $path
 * @param int $uid
 * @param int $gid
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_chown(UVLoop $loop, string $path, int $uid, int $gid, callable $callback)
{
}

/**
 * Async fchown.
 *
 * @param UVLoop $loop uv loop handle.
 * @param resource $fd
 * @param int $uid
 * @param int $gid
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_fchown(UVLoop $loop, $fd, int $uid, int $gid, callable $callback)
{
}

/**
 * Async link.
 *
 * @param UVLoop $loop uv loop handle.
 * @param string $from
 * @param string $to
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_link(UVLoop $loop, string $from, string $to, callable $callback)
{
}

/**
 * Async symlink.
 *
 * @param UVLoop $loop uv loop handle.
 * @param string $from
 * @param string $to
 * @param int $flags
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_symlink(UVLoop $loop, string $from, string $to, int $flags, callable $callback)
{
}

/**
 * Async readlink.
 *
 * @param UVLoop $loop uv loop handle
 * @param string $path
 * @param callable $callback
 *
 * @return void
 */
function uv_fs_readlink(UVLoop $loop, string $path, callable $callback)
{
}

/**
 * Async readdir.
 *
 * @param UVLoop $loop  uv loop handle
 * @param string $path
 * @param int $flags
 * @param callable $callback
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
 * @param callable $callback
 * @param int $flags
 *
 * @return resource
 */
function uv_fs_event_init(UVLoop $loop, string $path, callable $callback, int $flags = 0)
{
}

/**
 * Initialize tty resource. you have to open tty your hand.
 *
 * @param UVLoop $loop uv loop handle.
 * @param resource $fd
 * @param int $readable
 *
 * @return resource
 */
function uv_tty_init(UVLoop $loop, $fd, int $readable)
{
}

/**
 * @param resource $tty
 * @param int $width
 * @param int $height
 *
 * @return int
 */
function uv_tty_get_winsize($tty, int &$width, int &$height)
{
}

/**
 * @param resource $tty
 * @param int $mode
 *
 * @return int
 */
function uv_tty_set_mode($tty, int $mode)
{
}

/**
 * @return void
 */
function uv_tty_reset_mode()
{
}

/**
 * @param resource $uv_sockaddr
 *
 * @return string
 */
function uv_tcp_getsockname($uv_sockaddr)
{
}

/**
 * @param resource $uv_sockaddr
 *
 * @return string
 */
function uv_tcp_getpeername($uv_sockaddr)
{
}

/**
 * @param resource $uv_sockaddr
 *
 * @return string
 */
function uv_udp_getsockname($uv_sockaddr)
{
}

/**
 * @return int
 */
function uv_resident_set_memory()
{
}

/**
 * @param resource $address
 *
 * @return string
 */
function uv_ip4_name($address)
{
}

/**
 * @param resource $address
 *
 * @return string
 */
function uv_ip6_name($address)
{
}

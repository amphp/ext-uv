<?php

/**
 * create a `new` loop handle.
 *
 * @return uv_loop
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
 * @return uv_loop
 */
function uv_default_loop()
{
}

/**
 * This function runs the event loop. It will act differently depending on the
 * specified `$mode`.
 *
 * @param uv_loop $loop
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
function uv_run(uv_loop $loop = null, int $mode = UV::RUN_DEFAULT)
{
}

/**
 * start polling.
 *
 * If you want to use a socket. please use uv_poll_init_socket instead of this. Windows can't handle socket with this function.
 *
 * @param uv_poll $poll
 * @param int $events UV::READABLE and UV::WRITABLE flags.
 * @param callable $callback expects (uv_poll $poll, int $status, int $events, mixed $connection)
 * - the connection parameter passes uv_poll_init `$fd`.
 */
function uv_poll_start(uv_poll $poll, $events, ?callable $callback = null)
{
}

/**
 * Initialize the poll watcher using a socket descriptor. On unix this is
 * identical to uv_poll_init. On windows it takes a SOCKET handle.
 *
 * @param uv_loop $loop
 * @param resource $socket
 *
 * @return uv_poll
 */
function uv_poll_init_socket(uv_loop $loop, $socket)
{
}

/**
 * Initialize poll
 *
 * @param uv_loop $loop
 * @param resource $fd PHP `stream`, or `socket`
 *
 * @return uv_poll
 */
function uv_poll_init(uv_loop $loop, $fd)
{
}

/**
 * Stops polling the file descriptor.
 *
 * @param uv_poll $poll
 */
function uv_poll_stop(uv_poll $poll)
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
 * @param uv_handle $handle
 * @param callable $callback - expects (uv_handle $handle, int $status)
 */
function uv_close(uv_handle $handle, ?callable $callback = null)
{
}

/**
 * shutdown uv handle.
 *
 * @param uv_handle $handle
 * @param callable $callback - expects (uv_handle $handle, int $status)
 */
function uv_shutdown(uv_handle $handle, ?callable $callback = null)
{
}

/**
 * initialize timer handle.
 *
 * @param uv_loop $loop
 *
 * @return uv_timer
 */
function uv_timer_init(uv_loop $loop)
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
 * @param uv_timer $timer
 * @param float $timeout
 * @param float $repeat
 * @param callable $callback expects (uv_timer $timer, int$status)
 */
function uv_timer_start(uv_timer $timer, float $timeout, float $repeat, callable $callback)
{
}

/**
 * stop specified timer.
 *
 * @param uv_timer $timer
 *
 * @return float
 */
function uv_timer_stop(uv_timer $timer)
{
}

/**
 * Stop the event loop, causing uv_run() to end as soon as possible.
 * This will happen not sooner than the next loop iteration.
 * If this function was called before blocking for i/o,
 * the loop won’t block for i/o on this iteration.
 *
 * @param uv_loop $loop
 */
function uv_stop(uv_loop $loop)
{
}

/**
 * send buffer to specified resource `$handle`.
 *
 * @param uv_handle $handle
 * @param string $data
 * @param callable $callback expects (uv_handle $handle, int $status)
 */
function uv_write(uv_handle $handle, string $data, callable $callback)
{
}

/**
 * starts read callback for uv resources `$handle`.
 *
 * @param uv_handle $handle
 * @param callable $callback expects (uv_handle $handle, int $read, string buffer)
 */
function uv_read_start(uv_handle $handle, callable $callback)
{
}

/**
 * open specified file,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param uv_loop $loop
 * @param string $path file path
 * @param string $flag this should be `UV::O_RDONLY `and some constants flag
 * - `UV::O_WRONLY` | `UV::O_CREAT` | `UV::O_APPEND `| `UV::S_IRWXU` | `UV::S_IRUSR`
 * @param int $mode this should be UV::S_IRWXU and some mode flag
 * @param callable $callback expects (resource $stream)
 */
function uv_fs_open(uv_loop $loop, string $path, int $flag, int $mode, callable $callback)
{
}

/**
 * close specified file descriptor.
 *
 * @param uv_loop $loop
 * @param resource $fd PHP `stream`, or `socket`
 * @param callable $callback expects (resource $stream)
 */
function uv_fs_close(uv_loop $loop, $fd, callable $callback)
{
}

/**
 * async read,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param uv_loop $loop
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
function uv_fs_read(uv_loop $loop, $fd, int $offset, int $length, callable $callback)
{
}

/**
 * async write,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param uv_loop $loop
 * @param resource $fd PHP `stream`, or `socket`
 * @param string $buffer data
 * @param callable $callback expects (resource $stream, int $status)
 */
function uv_fs_write(uv_loop $loop, $fd, string $buffer, int $offset, callable $callback)
{
}

/**
 * async stat,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param uv_loop $loop
 * @param string $path
 * @param callable $callback expects (resource $stream, int $stat)
 */
function uv_fs_stat(uv_loop $loop, string $path, callable $callback)
{
}

/**
 * async lstat,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param uv_loop $loop
 * @param string $path
 * @param callable $callback expects (resource $stream, int $stat)
 */
function uv_fs_lstat(uv_loop $loop, string $path, callable $callback)
{
}

/**
 * async fstat,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param uv_loop $loop
 * @param resource $fd
 * @param callable $callback expects (resource $stream, int $stat)
 */
function uv_fs_fstat(uv_loop $loop, $fd, callable $callback)
{
}

/**
 * async fstat,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param uv_loop $loop
 * @param resource $out_fd
 * @param resource $in_fd
 * @param int $offset
 * @param int $length
 * @param callable $callback expects ($result)
 */
function uv_fs_sendfile(uv_loop $loop, $out_fd, $in_fd, int $offset, int $length, callable $callback)
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
 * - A uv_pipe_t, uv_tcp_t, uv_udp_t, etc. handle - basically any handle that
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
 * @param uv_handle $handle
 *
 * @return bool
 */
function uv_is_active(uv_handle $handle)
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
 * @param uv_poll $poll
 * @param callable $callback expects (uv_poll $poll, $status, $old, $new)
 * @param string $path
 */
function uv_fs_poll_start(uv_poll $poll, $callback, string $path, int $interval)
{
}

/**
 * Stop file system polling for changes.
 *
 * @param uv_poll $poll
 */
function uv_fs_poll_stop(uv_poll $poll)
{
}

/**
 * initialize file system poll handle.
 *
 * @param uv_loop $loop
 *
 * @return uv_poll
 */
function uv_fs_poll_init(uv_loop $loop)
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
 * @param uv_loop $loop
 *
 * @return uv_signal
 */
function uv_signal_init(uv_loop $loop)
{
}

/**
 * Start the signal handle with the given callback, watching for the given signal.
 *
 * @param uv_signal $handle
 * @param callable $callback
 * @param int $signal
 */
function uv_signal_start(uv_signal $handle, callable $callback, int $signal)
{
}

/**
 * Stop the signal handle, the callback will no longer be called.
 *
 * @param uv_signal $handle
 *
 * @return int
 */
function uv_signal_stop(uv_signal $handle)
{
}

/**
 * Initializes the process handle and starts the process.
 *
 * @param uv_loop $loop
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
 * - Expects (uv_process $process, $stat, $signal)
 * @param null|int $flags stdio flags
 * - Flags specifying how the stdio container should be passed to the child.
 * @param null|array $options
 *
 * @return uv_process
 */
function uv_spawn(
    uv_loop $loop,
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
 * @param uv_process $process
 * @param int $signal
 */
function uv_process_kill(uv_process $process, int $signal)
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
 * initialize pipe resource
 *
 * @param uv_loop $loop
 * @param bool $ipc when use for ipc, set `true` otherwise `false`.
 * - Note: needs to `false` on Windows for proper operations.
 *
 * @return uv_pipe
 */
function uv_pipe_init(uv_loop $loop, bool $ipc)
{
}

/**
 * open a pipe resource.
 *
 * @param uv_pipe $handle
 * @param int $pipe: dunnno. maybe file descriptor.
 */
function uv_pipe_open(uv_pipe $handle, int $pipe)
{
}

/**
 * @param resource $fd
 * @param integer $flags
 * @return resource $stdio
 */
function uv_stdio_new($fd, int $flags)
{
}

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
function uv_timer_init(UVLoop $loop)
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
function uv_signal_init(UVLoop $loop)
{
}

/**
 * Start the signal handle with the given callback, watching for the given signal.
 *
 * @param UVSignal $handle
 * @param callable $callback
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
 * initialize pipe resource
 *
 * @param UVLoop $loop
 * @param bool $ipc when use for ipc, set `true` otherwise `false`.
 * - Note: needs to `false` on Windows for proper operations.
 *
 * @return UVPipe
 */
function UVPipe_init(UVLoop $loop, bool $ipc)
{
}

/**
 * open a pipe resource.
 *
 * @param UVPipe $handle
 * @param int $pipe: dunnno. maybe file descriptor.
 */
function UVPipe_open(UVPipe $handle, int $pipe)
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

<?php

/**
 * create a `new` loop resource handle.
 *
 * @return resource $loop
 */
function uv_loop_new()
{
}

/**
 * return `default` loop resource handle.
 *
 * @return resource $loop
 */
function uv_default_loop()
{
}

/**
 * This function runs the event loop. It will act differently depending on the
 * specified `$mode`.
 *
 * @param resource $loop
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
function uv_run($loop = null, int $mode = UV::RUN_DEFAULT)
{
}

/**
 * start polling.
 *
 * If you want to use a socket. please use uv_poll_init_socket instead of this. Windows can't handle socket with this function.
 *
 * @param resource $poll
 * @param int $events UV::READABLE and UV::WRITABLE flags.
 * @param callable $callback expects (resource $poll, int $status, int $events, mixed $connection)
 * - the connection parameter passes uv_poll_init `$fd`.
 */
function uv_poll_start($poll, $events, ?callable $callback = null)
{
}

/**
 * Initialize the poll watcher using a socket descriptor. On unix this is
 * identical to uv_poll_init. On windows it takes a SOCKET handle.
 *
 * @param resource $loop
 * @param resource $socket
 *
 * @return resource $poll
 */
function uv_poll_init_socket($loop, $socket)
{
}

/**
 * Initialize poll
 *
 * The uv_poll watcher is used to watch file descriptors for readability and
 * writability, similar to the purpose of poll(2).
 *
 * The purpose of uv_poll is to enable integrating external libraries that
 * rely on the event loop to signal it about the socket status changes, like
 * c-ares or libssh2. Using uv_poll_t for any other other purpose is not
 * recommended; uv_tcp_t, uv_udp_t, etc. provide an implementation that is
 * much faster and more scalable than what can be achieved with uv_poll_t,
 * especially on Windows.
 *
 * It is possible that uv_poll occasionally signals that a file descriptor is
 * readable or writable even when it isn't. The user should therefore always
 * be prepared to handle EAGAIN or equivalent when it attempts to read from or
 * write to the fd.
 *
 * It is not okay to have multiple active uv_poll watchers for the same socket.
 * This can cause libuv to busyloop or otherwise malfunction.
 *
 * The user should not close a file descriptor while it is being polled by an
 * active uv_poll watcher. This can cause the poll watcher to report an error,
 * but it might also start polling another socket. However the fd can be safely
 * closed immediately after a call to uv_poll_stop() or uv_close().
 *
 * On windows only sockets can be polled with uv_poll. On unix any file
 * descriptor that would be accepted by poll(2) can be used with uv_poll.
 *
 * @param resource $loop
 * @param resource $fd PHP `stream`, or `socket`
 *
 * @return resource $poll
 */
function uv_poll_init($loop, $fd)
{
}

/**
 * Stops polling the file descriptor.
 *
 * @param resource $poll
 */
function uv_poll_stop($poll)
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
 * @param resource $handle
 * @param callable $callback - expects (resource $handle, int $status)
 */
function uv_close(uv_resource $handle, ?callable $callback = null)
{
}

/**
 * shutdown uv handle.
 *
 * @param resource $handle
 * @param callable $callback - expects (resource $handle, int $status)
 */
function uv_shutdown(uv_resource $handle, ?callable $callback = null)
{
}

/**
 * initialize timer handle.
 *
 * @param resource $loop
 *
 * @return resource $timer
 */
function uv_timer_init($loop)
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
 * @param resource $timer
 * @param float $timeout
 * @param float $repeat
 * @param callable $callback expects (resource $timer, int$status)
 */
function uv_timer_start($timer, float $timeout, float $repeat, callable $callback)
{
}

/**
 * stop specified timer.
 *
 * @param resource $timer
 *
 * @return float
 */
function uv_timer_stop($timer)
{
}

/**
 * Stop the event loop, causing uv_run() to end as soon as possible.
 * This will happen not sooner than the next loop iteration.
 * If this function was called before blocking for i/o,
 * the loop won’t block for i/o on this iteration.
 *
 * @param resource $loop
 */
function uv_stop($loop)
{
}

/**
 * send buffer to specified resource `$handle`.
 *
 * @param resource $handle
 * @param string $data
 * @param callable $callback expects (resource $handle, int $status)
 */
function uv_write(uv_resource $handle, string $data, callable $callback)
{
}

/**
 * starts read callback for uv resources `$handle`.
 *
 * @param resource $handle
 * @param callable $callback expects (resource $handle, int $read, string buffer)
 */
function uv_read_start(uv_resource $handle, callable $callback)
{
}

/**
 * open specified file,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param resource $loop
 * @param string $path file path
 * @param string $flag this should be `UV::O_RDONLY `and some constants flag
 * - `UV::O_WRONLY` | `UV::O_CREAT` | `UV::O_APPEND `| `UV::S_IRWXU` | `UV::S_IRUSR`
 * @param int $mode this should be UV::S_IRWXU and some mode flag
 * @param callable $callback expects (resource $stream)
 */
function uv_fs_open($loop, string $path, int $flag, int $mode, callable $callback)
{
}

/**
 * close specified file descriptor.
 *
 * @param resource $loop
 * @param resource $fd PHP `stream`, or `socket`
 * @param callable $callback expects (resource $stream)
 */
function uv_fs_close($loop, $fd, callable $callback)
{
}

/**
 * async read,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param resource $loop
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
function uv_fs_read($loop, $fd, int $offset, int $length, callable $callback)
{
}

/**
 * async write,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param resource $loop
 * @param resource $fd PHP `stream`, or `socket`
 * @param string $buffer data
 * @param callable $callback expects (resource $stream, int $status)
 */
function uv_fs_write($loop, $fd, string $buffer, int $offset, callable $callback)
{
}

/**
 * async stat,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param resource $loop
 * @param string $path
 * @param callable $callback expects (resource $stream, int $stat)
 */
function uv_fs_stat($loop, string $path, callable $callback)
{
}

/**
 * async lstat,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param resource $loop
 * @param string $path
 * @param callable $callback expects (resource $stream, int $stat)
 */
function uv_fs_lstat($loop, string $path, callable $callback)
{
}

/**
 * async fstat,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param resource $loop
 * @param resource $fd
 * @param callable $callback expects (resource $stream, int $stat)
 */
function uv_fs_fstat($loop, $fd, callable $callback)
{
}

/**
 * async fstat,
 * execute a blocking system call asynchronously (in a thread pool) and call the specified callback in the specified loop after completion.
 *
 * @param resource $loop
 * @param resource $out_fd
 * @param resource $in_fd
 * @param int $offset
 * @param int $length
 * @param callable $callback expects ($result)
 */
function uv_fs_sendfile($loop, $out_fd, $in_fd, int $offset, int $length, callable $callback)
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
 * @param resource $handle
 *
 * @return bool
 */
function uv_is_active(uv_resource $handle)
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
 * @param resource $poll
 * @param callable $callback expects ($poll, $status, $old, $new)
 * @param string $path
 */
function uv_fs_poll_start($poll, $callback, string $path, int $interval)
{
}

/**
 * Stop file system polling for changes.
 *
 * @param resource $poll
 */
function uv_fs_poll_stop($poll)
{
}

/**
 * initialize file system poll handle.
 *
 * @param resource $loop
 *
 * @return resource $poll
 */
function uv_fs_poll_init($loop)
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
 * UNIX signal handling on a per-event loop basis. The implementation is not
 * ultra efficient so don't go creating a million event loops with a million
 * signal watchers.
 *
 * Note to Linux users: `SIGRT0` and `SIGRT1` (signals 32 and 33) are used by the
 * NPTL pthreads library to manage threads. Installing watchers for those
 * signals will lead to unpredictable behavior and is strongly discouraged.
 * Future versions of libuv may simply reject them.
 *
 * Some signal support is available on Windows:
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
 *
 * @param resource $loop
 *
 * @return resource $signalHandle
 */
function uv_signal_init($loop)
{
}

/**
 * Start the signal handle with the given callback, watching for the given signal.
 *
 * @param resource $signalHandle
 * @param callable $callback
 * @param int $signal
 */
function uv_signal_start($signalHandle, callable $callback, int $signal)
{
}

/**
 * Stop the signal handle, the callback will no longer be called.
 *
 * @param resource $signalHandle
 *
 * @return int
 */
function uv_signal_stop($signalHandle)
{
}

/**
 * Initializes the process handle and starts the process.
 *
 * @param resource $loop
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
 * - Expects ($process, $stat, $signal)
 * @param null|int $flags stdio flags
 * - Flags specifying how the stdio container should be passed to the child.
 * @param null|array $options
 *
 * @return resource $process
 */
function uv_spawn(
    $loop,
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
 * send signal to specified uv process resource.
 *
 * @param resource $process
 * @param int $signal
 */
function uv_process_kill($process, int $signal)
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
 * @param resource $loop
 * @param bool $ipc when use for ipc, set true otherwise false.
 *
 * @return uv_resource $pipe
 */
function uv_pipe_init($loop, bool $ipc)
{
}

/**
 * open a pipe resource.
 *
 * @param resource $handle
 * @param int $pipe: dunnno. maybe file descriptor.
 */
function uv_pipe_open($handle, int $pipe)
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

/**
 * UV handle data type.
 * - uv_tcp,
 * - uv_udp,
 * - uv_pipe,
 * - ...etc
 */
interface uv_resource
{
}

/**
 * Full-featured event loop backed by epoll, kqueue, IOCP, event ports.
 * - Asynchronous TCP and UDP sockets
 * - Asynchronous DNS resolution
 * - Asynchronous file and file system operations
 * - File system events
 * - ANSI escape code controlled TTY
 * - IPC with socket sharing, using Unix domain sockets or named pipes (Windows)
 * - Child processes
 * - Thread pool
 * - Signal handling
 * - High resolution clock
 * - Threading and synchronization primitives
 *
 * @see https://libuv.org/
 */
final class UV
{
    /**
     * This flag indicates an event that becomes active when the provided file
     * descriptor(usually a stream resource, or socket) is ready for reading.
     */
    const READABLE = 1;

    /**
     * This flag indicates an event that becomes active when the provided file
     * descriptor(usually a stream resource, or socket) is ready for reading.
     */
    const WRITABLE = 2;

    /**
     * Runs the event loop until there are no more active and referenced
     * handles or requests.
     * Mode used to run the loop with.
     */
    const RUN_DEFAULT = 0;

    /**
     * Poll for i/o once. Note that this function blocks
     * if there are no pending callbacks.
     * Mode used to run the loop with.
     */
    const RUN_ONCE = 1;

    /**
     * Poll for i/o once but don’t block if there are no pending callbacks.
     * Mode used to run the loop with.
     */
    const RUN_NOWAIT = 2;

    /**
     * FS Event monitor type
     */
    const CHANGE = 1;

    /**
     * FS Event monitor type
     */
    const RENAME = 2;

    /**
     * Open the file for read-only access.
     */
    const O_RDONLY = 1;

    /**
     * Open the file for write-only access.
     */
    const O_WRONLY = 2;

    /**
     * Open the file for read-write access.
     */
    const O_RDWR = 3;

    /**
     * The file is created if it does not already exist.
     */
    const O_CREAT = 4;

    /**
     * If the O_CREAT flag is set and the file already exists,
     * fail the open.
     */
    const O_EXCL = 5;

    /**
     * If the file exists and is a regular file, and the file is
     * opened successfully for write access, its length shall be truncated to zero.
     */
    const O_TRUNC = 6;

    /**
     * The file is opened in append mode. Before each write,
     * the file offset is positioned at the end of the file.
     */
    const O_APPEND = 7;

    /**
     * If the path identifies a terminal device, opening the path will not cause that
     * terminal to become the controlling terminal for the process (if the process does
     * not already have one).
     *
     * - Note O_NOCTTY is not supported on Windows.
     */
    const O_NOCTTY = 8;

    /**
     * read, write, execute/search by owner
     */
    const S_IRWXU = 00700;

    /**
     * read permission, owner
     */
    const S_IRUSR = 00400;

    /**
     * write permission, owner
     */
    const S_IWUSR = 00200;

    /**
     * execute/search permission, owner
     */
    const S_IXUSR = 00100;

    /**
     * read, write, execute/search by group
     */
    const S_IRWXG = 00070;

    /**
     * read permission, group
     */
    const S_IRGRP = 00040;

    /**
     * write permission, group
     */
    const S_IWGRP = 00020;

    /**
     * execute/search permission, group
     */
    const S_IXGRP = 00010;

    /**
     * read, write, execute/search by others
     */
    const S_IRWXO = 00007;

    /**
     * read permission, others
     */
    const S_IROTH = 00004;

    /**
     * write permission, others
     */
    const S_IWOTH = 00002;

    /**
     * execute/search permission, others
     */
    const S_IXOTH = 00001;

    const AF_INET = 1;
    const AF_INET6 = 2;
    const AF_UNSPEC = 3;

    const LEAVE_GROUP = 1;
    const JOIN_GROUP = 2;

    /**
     * Flags specifying how a stdio should be transmitted to the child process.
     */
    const IGNORE         = 0x00;

    /**
     * Flags specifying how a stdio should be transmitted to the child process.
     */
    const CREATE_PIPE    = 0x01;

    /**
     * Flags specifying how a stdio should be transmitted to the child process.
     */
    const INHERIT_FD     = 0x02;

    /**
     * Flags specifying how a stdio should be transmitted to the child process.
     */
    const INHERIT_STREAM = 0x04;

    /**
     * When `UV::CREATE_PIPE` is specified, `UV::READABLE_PIPE` and `UV::WRITABLE_PIPE`
     * determine the direction of flow, from the child process' perspective. Both
     * flags may be specified to create a duplex data stream.
     */
    const READABLE_PIPE  = 0x10;
    const WRITABLE_PIPE  = 0x20;

    /**
     * Open the child pipe handle in overlapped mode on Windows.
     * On Unix it is silently ignored.
     */
    const OVERLAPPED_PIPE   = 0x40;

    /**
     *  Disables dual stack mode.
     */
    const UDP_IPV6ONLY = 1;

    /**
     * Indicates message was truncated because read buffer was too small. The
     * remainder was discarded by the OS. Used in uv_udp_recv_cb.
     */
    const UDP_PARTIAL = 2;

    /**
     * Set the child process' user id.
     */
    const PROCESS_SETUID = (1 << 0);

    /**
     * Set the child process' group id.
     */
    const PROCESS_SETGID = (1 << 1);

    /**
     * Do not wrap any arguments in quotes, or perform any other escaping, when
     * converting the argument list into a command line string. This option is
     * only meaningful on Windows systems. On Unix it is silently ignored.
     */
    const PROCESS_WINDOWS_VERBATIM_ARGUMENTS = (1 << 2);

    /**
     * Spawn the child process in a detached state - this will make it a process
     * group leader, and will effectively enable the child to keep running after
     * the parent exits. Note that the child process will still keep the
     * parent's event loop alive unless the parent process calls uv_unref() on
     * the child's process handle.
     */
    const PROCESS_DETACHED = (1 << 3);

    /**
     * Hide the subprocess window that would normally be created. This option is
     * only meaningful on Windows systems. On Unix it is silently ignored.
     */
    const PROCESS_WINDOWS_HIDE = (1 << 4);

    /**
     * Hide the subprocess console window that would normally be created. This
     * option is only meaningful on Windows systems. On Unix it is silently
     * ignored.
     */
    const PROCESS_WINDOWS_HIDE_CONSOLE = (1 << 5);

    /**
     * Hide the subprocess GUI window that would normally be created. This
     * option is only meaningful on Windows systems. On Unix it is silently
     * ignored.
     */
    const PROCESS_WINDOWS_HIDE_GUI = (1 << 6);
}

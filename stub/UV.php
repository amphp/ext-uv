<?php

/**
 * Base handle type for `libuv` handles.
 * All handle types (including stream types) subclass
 * - UVTcp,
 * - UVUdp,
 * - UVPipe,
 * - ...etc
 *
 * All API functions defined here work with any handle type.
 * `Libuv` handles are not movable. Pointers to handle structures passed
 * to functions must remain valid for the duration of the requested operation.
 * Take care when using stack allocated handles.
 *
 * This is a full-featured event loop backed by epoll, kqueue, IOCP, event ports.
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
abstract class UV
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

    /**
     * Initial/normal terminal mode
     */
    const TTY_MODE_NORMAL = 0;

    /**
     * Raw input mode (On Windows, ENABLE_WINDOW_INPUT is also enabled)
     */
    const TTY_MODE_RAW = 1;

    /**
     * Binary-safe I/O mode for IPC (Unix-only)
     */
    const TTY_MODE_IO = 2;

    /**
     * The SIGHUP signal is sent to a process when its controlling terminal is closed. It was originally designed to
     * notify the process of a serial line drop (a hangup). In modern systems, this signal usually means that the
     * controlling pseudo or virtual terminal has been closed. Many daemons will reload their configuration files and
     * reopen their logfiles instead of exiting when receiving this signal. nohup is a command to make a command ignore
     * the signal.
     */
    const SIGHUP = 1;

    /**
     * The SIGINT signal is sent to a process by its controlling terminal when a user wishes to interrupt the process.
     * This is typically initiated by pressing Ctrl-C, but on some systems, the "delete" character or "break" key can be
     * used.
     */
    const SIGINT = 2;

    /**
     * The SIGQUIT signal is sent to a process by its controlling terminal when the user requests that the process quit
     * and perform a core dump.
     */
    const SIGQUIT = 3;

    /**
     * The SIGILL signal is sent to a process when it attempts to execute an illegal, malformed, unknown, or privileged
     * instruction.
     */
    const SIGILL = 4;

    /**
     * The SIGTRAP signal is sent to a process when an exception (or trap) occurs: a condition that a debugger has
     * requested to be informed of — for example, when a particular function is executed, or when a particular variable
     * changes value.
     */
    const SIGTRAP = 5;

    /**
     * The SIGABRT signal is sent to a process to tell it to abort, i.e. to terminate. The signal is usually initiated
     * by the process itself when it calls abort function of the C Standard Library, but it can be sent to the process
     * from outside like any other signal.
     */
    const SIGABRT = 6;

    const SIGIOT = 6;

    /**
     * The SIGBUS signal is sent to a process when it causes a bus error. The conditions that lead to the signal being
     * sent are, for example, incorrect memory access alignment or non-existent physical address.
     */
    const SIGBUS = 7;

    const SIGFPE = 8;

    /**
     * The SIGKILL signal is sent to a process to cause it to terminate immediately (kill). In contrast to SIGTERM and
     * SIGINT, this signal cannot be caught or ignored, and the receiving process cannot perform any clean-up upon
     * receiving this signal.
     */
    const SIGKILL = 9;

    /**
     * The SIGUSR1 signal is sent to a process to indicate user-defined conditions.
     */
    const SIGUSR1 = 10;

    /**
     * The SIGUSR1 signa2 is sent to a process to indicate user-defined conditions.
     */
    const SIGUSR2 = 12;

    /**
     * The SIGSEGV signal is sent to a process when it makes an invalid virtual memory reference, or segmentation fault,
     * i.e. when it performs a segmentation violation.
     */
    const SIGSEGV = 11;

    /**
     * The SIGPIPE signal is sent to a process when it attempts to write to a pipe without a process connected to the
     * other end.
     */
    const SIGPIPE = 13;

    /**
     * The SIGALRM, SIGVTALRM and SIGPROF signal is sent to a process when the time limit specified in a call to a
     * preceding alarm setting function (such as setitimer) elapses. SIGALRM is sent when real or clock time elapses.
     * SIGVTALRM is sent when CPU time used by the process elapses. SIGPROF is sent when CPU time used by the process
     * and by the system on behalf of the process elapses.
     */
    const SIGALRM = 14;

    /**
     * The SIGTERM signal is sent to a process to request its termination. Unlike the SIGKILL signal, it can be caught
     * and interpreted or ignored by the process. This allows the process to perform nice termination releasing
     * resources and saving state if appropriate. SIGINT is nearly identical to SIGTERM.
     */
    const SIGTERM = 15;

    const SIGSTKFLT = 16;
    const SIGCLD = 17;

    /**
     * The SIGCHLD signal is sent to a process when a child process terminates, is interrupted, or resumes after being
     * interrupted. One common usage of the signal is to instruct the operating system to clean up the resources used by
     * a child process after its termination without an explicit call to the wait system call.
     */
    const SIGCHLD = 17;

    /**
     * The SIGCONT signal instructs the operating system to continue (restart) a process previously paused by the
     * SIGSTOP or SIGTSTP signal. One important use of this signal is in job control in the Unix shell.
     */
    const SIGCONT = 18;

    /**
     * The SIGSTOP signal instructs the operating system to stop a process for later resumption.
     */
    const SIGSTOP = 19;

    /**
     * The SIGTSTP signal is sent to a process by its controlling terminal to request it to stop (terminal stop). It is
     * commonly initiated by the user pressing Ctrl+Z. Unlike SIGSTOP, the process can register a signal handler for or
     * ignore the signal.
     */
    const SIGTSTP = 20;

    /**
     * The SIGTTIN signal is sent to a process when it attempts to read in from the tty while in the background.
     * Typically, this signal is received only by processes under job control; daemons do not have controlling
     */
    const SIGTTIN = 21;

    /**
     * The SIGTTOU signal is sent to a process when it attempts to write out from the tty while in the background.
     * Typically, this signal is received only by processes under job control; daemons do not have controlling
     */
    const SIGTTOU = 22;

    /**
     * The SIGURG signal is sent to a process when a socket has urgent or out-of-band data available to read.
     */
    const SIGURG = 23;

    /**
     * The SIGXCPU signal is sent to a process when it has used up the CPU for a duration that exceeds a certain
     * predetermined user-settable value. The arrival of a SIGXCPU signal provides the receiving process a chance to
     * quickly save any intermediate results and to exit gracefully, before it is terminated by the operating system
     * using the SIGKILL signal.
     */
    const SIGXCPU = 24;

    /**
     * The SIGXFSZ signal is sent to a process when it grows a file larger than the maximum allowed size
     */
    const SIGXFSZ = 25;

    /**
     * The SIGVTALRM signal is sent to a process when the time limit specified in a call to a preceding alarm setting
     * function (such as setitimer) elapses. SIGVTALRM is sent when CPU time used by the process elapses.
     */
    const SIGVTALRM = 26;

    /**
     * The SIGPROF signal is sent to a process when the time limit specified in a call to a preceding alarm setting
     * function (such as setitimer) elapses. SIGPROF is sent when CPU time used by the process and by the system on
     * behalf of the process elapses.
     */
    const SIGPROF = 27;

    /**
     * The SIGWINCH signal is sent to a process when its controlling terminal changes its size (a window change).
     */
    const SIGWINCH = 28;

    /**
     * The SIGPOLL signal is sent when an event occurred on an explicitly watched file descriptor. Using it effectively
     * leads to making asynchronous I/O requests since the kernel will poll the descriptor in place of the caller. It
     * provides an alternative to active polling.
     */
    const SIGPOLL = 29;

    const SIGIO = 29;

    /**
     * The SIGPWR signal is sent to a process when the system experiences a power failure.
     */
    const SIGPWR = 30;

    /**
     * The SIGSYS signal is sent to a process when it passes a bad argument to a system call. In practice, this kind of
     * signal is rarely encountered since applications rely on libraries (e.g. libc) to make the call for them.
     */
    const SIGSYS = 31;

    const SIGBABY = 31;

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
}

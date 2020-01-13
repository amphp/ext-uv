<?php

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
}

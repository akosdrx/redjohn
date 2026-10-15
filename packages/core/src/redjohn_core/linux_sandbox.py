"""Unprivileged offline Linux execution: Landlock + a seccomp allowlist.

This module is an isolated child entrypoint, never applied in the engine process.
No namespaces or capabilities are required. Landlock ABI >= 3 is mandatory so
truncate and cross-directory references are mediated. libseccomp installs only
the native architecture and rejects other ABIs. Every failure precedes exec.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import platform
import re
import stat
import sys
import sysconfig
from pathlib import Path

# Linux generic syscall numbers shared by x86_64 and aarch64.
_CREATE, _ADD, _RESTRICT = 444, 445, 446
_EXEC, _WRITE, _READ, _READDIR = 1, 2, 4, 8
_FS_V3 = (1 << 15) - 1
_SAFE_WORK = _FS_V3 & ~((1 << 6) | (1 << 9) | (1 << 10) | (1 << 11))
_ALLOW, _ERRNO = 0x7FFF0000, 0x00050000


class Unavailable(RuntimeError):
    pass


class _Ruleset(ctypes.Structure):
    _fields_ = [('handled_access_fs', ctypes.c_uint64)]


class _PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('allowed_access', ctypes.c_uint64), ('parent_fd', ctypes.c_int)]


class _Arg(ctypes.Structure):
    _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_int),
                ('datum_a', ctypes.c_uint64), ('datum_b', ctypes.c_uint64)]


def _libc():
    lib = ctypes.CDLL(None, use_errno=True)
    lib.syscall.restype = ctypes.c_long
    return lib


def abi_version() -> int:
    if sys.platform != 'linux' or platform.machine() not in ('x86_64', 'aarch64'):
        return 0
    return int(_libc().syscall(_CREATE, 0, 0, 1))


def _seccomp_library() -> str | None:
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller cannot discover a library loaded through a variable.
        # The Linux build explicitly bundles it; do not require a host package.
        bundled = Path(sys._MEIPASS) / 'libseccomp.so.2'
        return str(bundled) if bundled.is_file() else None
    return ctypes.util.find_library('seccomp')


def capability() -> dict[str, str | bool]:
    abi = abi_version()
    available = abi >= 3 and _seccomp_library() is not None
    return {'available': available, 'backend': 'landlock+seccomp', 'network': 'denied',
            'detail': f'Landlock ABI {abi}; offline syscall allowlist' if available else
            'offline executor requires Landlock ABI >= 3 and libseccomp2 (x86_64/aarch64)'}


def _stdlib_paths(executable: Path) -> set[Path]:
    paths = {Path(sysconfig.get_path('stdlib'))}
    # A frozen engine's stdlib lives in its bundle. A selected system Python
    # needs its own known standard modules too; never probe it by executing
    # untrusted argv before confinement, and never expose its site-packages.
    if (executable.parent in (Path('/usr/bin'), Path('/usr/local/bin'))
            and re.fullmatch(r'python3\.\d+', executable.name)):
        paths.add(executable.parent.parent / 'lib' / executable.name)
    return paths


def _read_paths(executable: Path) -> list[Path]:
    paths = [Path(p) for p in ('/usr/bin', '/usr/sbin', '/bin', '/sbin', '/etc/ld.so.cache')]
    # Resolve individual shared libraries, not a whole /usr/lib or /usr/local
    # tree. Those trees may also hold application configuration/private data.
    multiarch = sysconfig.get_config_var('MULTIARCH')
    library_dirs = [Path(p) for p in ('/lib', '/lib64', '/usr/lib', '/usr/lib64')]
    if multiarch:
        library_dirs.extend((Path('/lib') / multiarch, Path('/usr/lib') / multiarch))
    for directory in library_dirs:
        if directory.is_dir():
            paths.extend(p for p in directory.glob('*.so*') if p.is_file())
    paths.extend((executable, Path(sys.executable)))
    # Do not allow /usr/local or site-packages as a whole: they can contain app
    # credentials. Only standard-library modules and the exact Python shared
    # library are readable for an interpreter located outside system roots.
    for stdlib in _stdlib_paths(executable):
        for name in sys.stdlib_module_names:
            for candidate in (stdlib / name, stdlib / f'{name}.py'):
                if candidate.exists():
                    paths.append(candidate)
        paths.append(stdlib / 'lib-dynload')
    libdir, library = sysconfig.get_config_var('LIBDIR'), sysconfig.get_config_var('LDLIBRARY')
    if libdir and library:
        paths.append(Path(libdir) / library)
    if hasattr(sys, '_MEIPASS'):
        paths.append(Path(sys._MEIPASS))  # bundled read-only interpreter assets
    return list({p.resolve() for p in paths if p.exists()})


def _landlock(workdir: Path, executable: Path) -> None:
    libc = _libc()
    abi = abi_version()
    if abi < 3:
        raise Unavailable(f'Landlock ABI >= 3 required, received {abi}')
    attr = _Ruleset(_FS_V3)
    ruleset = libc.syscall(_CREATE, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if ruleset < 0:
        raise OSError(ctypes.get_errno(), 'landlock_create_ruleset')

    def add(path: Path, rights: int):
        fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        try:
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                rights &= _EXEC | _READ | _WRITE | (1 << 14)
            rule = _PathRule(rights, fd)
            if libc.syscall(_ADD, ruleset, 1, ctypes.byref(rule), 0) != 0:
                raise OSError(ctypes.get_errno(), f'landlock_add_rule: {path}')
        finally:
            os.close(fd)
    try:
        for path in _read_paths(executable):
            add(path, _EXEC | _READ | _READDIR)
        # Import machinery lists the stdlib directory to find allowed modules;
        # directory enumeration does not grant content access to site-packages.
        for stdlib in _stdlib_paths(executable):
            if stdlib.is_dir():
                add(stdlib, _READDIR)
        add(workdir, _SAFE_WORK)
        add(Path('/dev/null'), _READ | _WRITE)
        for name in ('/dev/random', '/dev/urandom'):
            add(Path(name), _READ)
        if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            raise OSError(ctypes.get_errno(), 'PR_SET_NO_NEW_PRIVS')
        if libc.syscall(_RESTRICT, ruleset, 0) != 0:
            raise OSError(ctypes.get_errno(), 'landlock_restrict_self')
    finally:
        os.close(ruleset)


# Default deny is intentional: new syscalls do not silently bypass containment.
# No socket/socketpair (including AF_UNIX), io_uring, ptrace/process_vm, pidfd,
# namespaces, mount/chroot, metadata mutation, signals to peers, or process-group
# detachment. Filesystem data access is additionally mediated by Landlock.
_SYSCALLS = '''read write readv writev pread64 pwrite64 preadv pwritev
close close_range lseek fstat newfstatat stat lstat statx access faccessat faccessat2
open openat openat2 getdents getdents64 readlink readlinkat dup dup2 dup3
unlink unlinkat rmdir mkdir mkdirat rename renameat renameat2 link linkat symlink symlinkat
truncate ftruncate fsync fdatasync flock
brk mmap mprotect munmap mremap madvise msync mincore
rt_sigaction rt_sigprocmask rt_sigreturn sigaltstack rt_sigsuspend rt_sigtimedwait restart_syscall
fork vfork execve execveat exit exit_group wait4 waitid
getpid getppid gettid getuid geteuid getgid getegid getgroups getpgrp
getrlimit getrusage clock_gettime clock_getres clock_nanosleep nanosleep gettimeofday times
uname sysinfo sched_yield sched_getaffinity futex futex_waitv set_tid_address set_robust_list rseq
getrandom membarrier arch_prctl
poll ppoll select pselect6 epoll_create epoll_create1 epoll_ctl epoll_wait epoll_pwait epoll_pwait2
eventfd eventfd2 timerfd_create timerfd_settime timerfd_gettime pipe pipe2 chdir fchdir getcwd umask
'''.split()


def _seccomp(library: str) -> None:
    lib = ctypes.CDLL(library, use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                          ctypes.c_uint, ctypes.POINTER(_Arg)]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    ctx = lib.seccomp_init(_ERRNO | errno.EPERM)
    if not ctx:
        raise Unavailable('seccomp_init failed')
    try:
        def rule(name, action=_ALLOW, comparison=None):
            number = lib.seccomp_syscall_resolve_name(name.encode())
            if number == -1:
                return  # absent syscall on this architecture remains denied
            result = lib.seccomp_rule_add_array(ctx, action, number,
                                                1 if comparison else 0,
                                                ctypes.byref(comparison) if comparison else None)
            if result != 0:
                raise Unavailable(f'seccomp rule {name}: {result}')
        for name in _SYSCALLS:
            rule(name)
        # Do not permit F_SETOWN/F_SETSIG, which could deliver SIGIO to peers.
        for command in (0, 1, 2, 3, 4, 5, 6, 7, 1030):
            rule('fcntl', comparison=_Arg(1, 4, command, 0))
        # clone3's flags are an indirect pointer; refuse it so libc uses clone,
        # where a scalar mask prevents all namespace creation and CLONE_UNTRACED.
        rule('clone3', _ERRNO | errno.ENOSYS)
        # CLONE_PARENT could escape the expected parent/child lifecycle. Only
        # ordinary SIGCHLD forks and signal-free pthread clones are permitted.
        # Allow only flags used by ordinary fork/vfork/pthread implementations:
        # VM, FS, FILES, SIGHAND, VFORK, THREAD, SYSVSEM, SETTLS, PARENT_SETTID,
        # CHILD_CLEARTID, CHILD_SETTID. Unknown future flags stay forbidden.
        clone_flags = 0x013D4F00
        clone_mask = 0xFFFFFFFFFFFFFFFF ^ clone_flags
        for exit_signal in (0, 17):
            rule('clone', comparison=_Arg(0, 7, clone_mask, exit_signal))
        rule('prlimit64', comparison=_Arg(0, 4, 0, 0))  # current process only
        if lib.seccomp_load(ctx) != 0:
            raise Unavailable('seccomp_load failed')
    finally:
        lib.seccomp_release(ctx)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(args) < 3 or args[1] != '--':
            raise Unavailable('usage: linux_sandbox WORKDIR -- EXECUTABLE [ARG...]')
        workdir, command = Path(args[0]).resolve(strict=True), args[2:]
        executable = Path(command[0]).resolve(strict=True)
        library = _seccomp_library()
        if not library:
            raise Unavailable('libseccomp2 is required')
        # The wrapper starts before untrusted code and is single-threaded. Drop
        # inherited descriptors before restricting paths; Landlock cannot revoke
        # access granted by descriptors opened outside its domain.
        for fd in (1, 2):
            if not stat.S_ISFIFO(os.fstat(fd).st_mode):
                raise Unavailable('sandbox stdout/stderr must be pipes')
        null = os.open('/dev/null', os.O_RDONLY)
        os.dup2(null, 0)
        for fd in list(map(int, os.listdir('/proc/self/fd'))):
            if fd > 2:
                try:
                    os.close(fd)
                except OSError:
                    pass
        os.chdir(workdir)
        _landlock(workdir, executable)
        _seccomp(library)
        # Caller environment is already bounded, but keep this entrypoint safe
        # when called directly too (no LD_PRELOAD/PYTHONPATH/provider secrets).
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(workdir), 'LANG': 'C.UTF-8',
               'TMPDIR': str(workdir)}
        os.execve(executable, command, env)
    except (OSError, Unavailable, ValueError) as exc:
        print(f'executor_unavailable: {exc}', file=sys.stderr)
        return 126
    return 126


if __name__ == '__main__':
    raise SystemExit(main())

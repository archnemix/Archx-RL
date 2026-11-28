"""Offline, private SQLite snapshot experiment. NOT a safe restore protocol.

All writers including older binaries must be stopped. A consistent snapshot is
not necessarily current later: it may omit later charges and resurrect consumed
replay tokens if restored. Never use this API to roll back a running store.
"""
import os
import sqlite3
import stat
import tempfile
from pathlib import Path

from sqlite_engine import SQLiteEngine


def snapshot(engine, destination):
    """Create a new private, consistent snapshot without overwriting a path.

    Operator must control all path ancestors, stop all writers and protect both
    database and backup. An advisory SQLite writer transaction prevents current
    SQLite clients from committing between verification and copying. A hostile
    local process or an old binary can still violate these assumptions. A later
    restore, freshness, secret custody, durability after power loss and safe
    rollback are not provided. A raised error after publication is ambiguous.
    """
    if not isinstance(engine, SQLiteEngine): raise ValueError('SQLiteEngine required')
    target = Path(destination).absolute()
    parent = target.parent
    if parent.resolve(strict=True) != parent:
        raise ValueError('Snapshot directory path must not traverse symlinks')
    info = parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('Snapshot directory must be private and owned by the service user')
    fd, temp = tempfile.mkstemp(prefix='.archx-snapshot-', dir=parent)
    os.close(fd)
    lock = None
    source = None
    try:
        lock = engine.connect()
        engine._begin_writer(lock)
        # Verify persistent metadata under the writer lock and capture a
        # consistent SQLite snapshot, including committed WAL frames.
        source = engine.connect()
        dest = sqlite3.connect(Path(temp).as_uri() + '?mode=rw', uri=True, isolation_level=None)
        try:
            source.backup(dest)
            if dest.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                raise ValueError('Snapshot integrity check failed')
            if dest.execute('PRAGMA foreign_key_check').fetchone() is not None:
                raise ValueError('Snapshot foreign key check failed')
            # Avoid depending on WAL sidecars when only the main file is saved.
            if dest.execute('PRAGMA journal_mode=DELETE').fetchone() != ('delete',):
                raise ValueError('Snapshot could not be made self-contained')
        finally:
            dest.close()
        source.close(); source = None
        if any(os.path.lexists(temp + suffix) for suffix in ('-journal', '-wal', '-shm')):
            raise ValueError('Snapshot still has SQLite sidecars')
        fd = os.open(temp, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
                raise ValueError('Unexpected snapshot file permissions')
            os.fsync(fd)
        finally:
            os.close(fd)
        # Atomic no-overwrite publication on the same filesystem. Source path
        # cannot be replaced because link() fails if destination already exists.
        os.link(temp, target, follow_symlinks=False)
        os.unlink(temp)
        temp = None
        dirfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try: os.fsync(dirfd)
        finally: os.close(dirfd)
        lock.commit()
    except BaseException:
        if lock is not None: lock.rollback()
        raise
    finally:
        if source is not None: source.close()
        if lock is not None: lock.close()
        if temp is not None:
            # SQLite may have created journal sidecars before an error. A hard
            # crash can still leave temporary files for operator inspection.
            for name in (temp, temp + '-journal', temp + '-wal', temp + '-shm'):
                try: os.unlink(name)
                except FileNotFoundError: pass

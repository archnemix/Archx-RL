"""Opt-in single-host prototype retention operations; not secure erasure.

Only explicitly configured legacy tables and a private backup directory are
eligible. Operations are separate, not a single transaction. Never use an
untrusted or concurrently writable backup directory.
"""
import math
import os
import re
import sqlite3
import stat
import time
from pathlib import Path

BACKUP_NAME = re.compile(r'^archx-backup-[0-9]{8}T[0-9]{6}Z\.sqlite$')
LEGACY_TABLES = {
    'trial_entitlements': 'CREATE TABLE trial_entitlements (id INTEGER PRIMARY KEY, account_token TEXT NOT NULL, offer_token TEXT NOT NULL, idem_token TEXT NOT NULL, request_token TEXT NOT NULL, created REAL NOT NULL, UNIQUE(account_token,offer_token), UNIQUE(account_token,idem_token))',
    'trial_signals': 'CREATE TABLE trial_signals (trial_id INTEGER NOT NULL REFERENCES trial_entitlements(id) ON DELETE CASCADE, name TEXT NOT NULL, token TEXT NOT NULL, expires REAL NOT NULL, PRIMARY KEY(trial_id,name))',
}


def purge_legacy(engine):
    """Irreversibly drop *all* recognized retired trial tables, not age-based rows.

    Caller must verify retirement, authorization, backup/recovery and legal
    retention requirements. Unknown/incomplete schemas fail closed.
    """
    con=engine.connect()
    try:
        con.execute('BEGIN IMMEDIATE')
        objects={name:(kind,sql) for kind,name,sql in con.execute("SELECT type,name,sql FROM sqlite_master WHERE name IN ('trial_entitlements','trial_signals')")}
        marker=con.execute("SELECT value FROM meta WHERE name='trial_policy_v1'").fetchone()
        if not objects and marker is None:
            con.commit(); return False
        if marker is None or len(objects)!=2 or any(objects.get(name)!=('table',sql) for name,sql in LEGACY_TABLES.items()):
            raise ValueError('Unrecognized legacy schema; operator review required')
        con.execute('DROP TABLE trial_signals')
        con.execute('DROP TABLE trial_entitlements')
        con.execute("DELETE FROM meta WHERE name='trial_policy_v1'")
        con.commit(); return True
    except BaseException:
        con.rollback(); raise
    finally:
        con.close()


def checkpoint(engine):
    """Passive WAL checkpoint; reports frames not yet copied, not erasure."""
    con=engine.connect()
    try:
        row=con.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone()
        if row is None or len(row)!=3 or any(type(n) is not int or n < 0 for n in row):
            raise sqlite3.OperationalError('Invalid checkpoint result')
        return {'checkpoint_busy':row[0], 'wal_frames':row[1], 'checkpointed_frames':row[2]}
    finally:
        con.close()


def prune_backups(directory, min_age_seconds, *, now=None):
    """Unlink up to 64 matching old files in a private, operator-owned directory.

    Only names listed in BACKUP_NAME and owned, private, single-link regular
    files without SQLite WAL/SHM/journal sidecars are eligible. Logical unlink
    is not secure physical erasure; concurrent directory modification is outside
    this prototype's trust model. Never point this at the active database.
    """
    if type(min_age_seconds) is not int or min_age_seconds < 86400:
        raise ValueError('Backup retention must be at least one day')
    now=time.time() if now is None else now
    if type(now) not in (int,float) or not math.isfinite(now): raise ValueError('Invalid retention clock')
    path=Path(directory)
    if not path.is_absolute(): raise ValueError('Backup directory must be absolute')
    fd=os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    removed=0; pending=False
    try:
        st=os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o077:
            raise ValueError('Backup directory must be private and owned by the service user')
        # A cap on removals does not bound the directory listing or its sort.
        names=set(os.listdir(fd))
        for name in sorted(names):
            if not BACKUP_NAME.fullmatch(name): continue
            if any(name+s in names for s in ('-wal','-shm','-journal')): continue
            try: item=os.stat(name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError: continue
            if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.geteuid() or item.st_mode & 0o077 or item.st_nlink!=1:
                continue
            if item.st_mtime > now or now-item.st_mtime < min_age_seconds: continue
            if removed==64: pending=True; break
            os.unlink(name,dir_fd=fd); removed+=1
        return {'backup_files_removed':removed,'backups_pending':pending}
    finally:
        os.close(fd)


class RetentionPlan:
    """Explicitly configured maintenance plan for IdleCleanup; no defaults delete backups."""
    def __init__(self, engine, *, replay=None, backup_dir=None, backup_min_age_seconds=None,
                 purge_retired_trial=False, checkpoint_wal=False, clock=time.time):
        if not callable(getattr(engine,'cleanup_expired',None)) or not callable(clock): raise ValueError('Invalid engine or clock')
        if replay is not None and not callable(getattr(replay,'cleanup_expired',None)): raise ValueError('Invalid replay store')
        if type(purge_retired_trial) is not bool or type(checkpoint_wal) is not bool: raise ValueError('Invalid flags')
        if (backup_dir is None) != (backup_min_age_seconds is None): raise ValueError('Backup directory and age must be supplied together')
        if backup_dir is not None and (not Path(backup_dir).is_absolute() or type(backup_min_age_seconds) is not int or backup_min_age_seconds < 86400):
            raise ValueError('Invalid backup retention')
        if (purge_retired_trial or checkpoint_wal) and not callable(getattr(engine,'connect',None)):
            raise ValueError('Legacy cleanup/checkpoint require SQLite')
        if backup_dir is not None and getattr(engine,'db_path',None) and Path(engine.db_path).resolve().parent == Path(backup_dir).resolve():
            raise ValueError('Backups must use a separate directory from the active database')
        self.engine,self.replay,self.backup_dir,self.backup_age,self.clock=engine,replay,backup_dir,backup_min_age_seconds,clock
        self.purge_retired_trial,self.checkpoint_wal=purge_retired_trial,checkpoint_wal

    def cleanup_expired(self):
        result=dict(self.engine.cleanup_expired())
        if self.replay is not None: result.update(self.replay.cleanup_expired())
        if self.purge_retired_trial: result['legacy_purged']=purge_legacy(self.engine)
        if self.backup_dir is not None: result.update(prune_backups(self.backup_dir,self.backup_age,now=self.clock()))
        if self.checkpoint_wal: result.update(checkpoint(self.engine))
        return result

"""Explicit, synthetic retention fixtures; unlink is not physical erasure."""
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'demo'))
from engine import Engine,policy
from sqlite_engine import SQLiteEngine
from replay import MemoryReplay,SQLiteReplay,ReplayUnavailable
from retention import LEGACY_TABLES,RetentionPlan,prune_backups,purge_legacy,checkpoint
from maintenance import IdleCleanup

SECRET=b'synthetic-retention-only-secret-123456789'

class RetentionTests(unittest.TestCase):
    def test_replay_idle_expiry_is_bounded_and_live_token_survives(self):
        for mode in ('memory','sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                now=[1000]
                e=Engine(policy(),secret=SECRET,clock=lambda:now[0]) if mode=='memory' else SQLiteEngine(Path(tmp)/'state.sqlite',policy(),SECRET,clock=lambda:now[0])
                replay=MemoryReplay(SECRET,lambda:now[0],capacity=200,per_peer=200) if mode=='memory' else SQLiteReplay(e,capacity=200,per_peer=200)
                old=[replay.issue('192.0.2.1') for _ in range(130)]
                now[0]=1030; live=replay.issue('192.0.2.1'); now[0]=1120
                self.assertEqual(replay.cleanup_expired(),{'challenges_pending':True})
                self.assertEqual(replay.cleanup_expired(),{'challenges_pending':True})
                self.assertEqual(replay.cleanup_expired(),{'challenges_pending':False})
                self.assertFalse(replay.consume(old[-1],'192.0.2.1'))
                self.assertTrue(replay.consume(live,'192.0.2.1'))
                self.assertFalse(replay.consume(live,'192.0.2.1'))
                now[0]=float('nan')
                with self.assertRaises(ValueError): replay.cleanup_expired()

    def test_backup_prune_is_opt_in_bounded_and_preserves_unsafe_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); now=2000000
            def file(name,mode=0o600,age=100000):
                p=directory/name; p.write_text('synthetic'); os.chmod(p,mode); os.utime(p,(now-age,now-age)); return p
            for i in range(70): file(f'archx-backup-20260101T{i:06d}Z.sqlite')
            open_backup=(directory/'archx-backup-20260101T000000Z.sqlite').open()
            young=file('archx-backup-20260202T000000Z.sqlite',age=3)
            public=file('archx-backup-20260203T000000Z.sqlite',mode=0o644)
            with_sidecar=file('archx-backup-20260204T000000Z.sqlite'); file(with_sidecar.name+'-wal')
            arbitrary=file('unrelated.sqlite')
            original=file('archx-backup-20260205T000000Z.sqlite'); hard=directory/'hardlink'; os.link(original,hard)
            symlink=directory/'archx-backup-20260206T000000Z.sqlite'; symlink.symlink_to(arbitrary)
            self.assertEqual(prune_backups(directory,86400,now=now),{'backup_files_removed':64,'backups_pending':True})
            self.assertFalse((directory/'archx-backup-20260101T000000Z.sqlite').exists())
            self.assertEqual(open_backup.read(),'synthetic')  # unlink is not physical erasure
            open_backup.close()
            self.assertEqual(prune_backups(directory,86400,now=now),{'backup_files_removed':6,'backups_pending':False})
            for p in (young,public,with_sidecar,arbitrary,original,hard,symlink): self.assertTrue(p.exists())
            with self.assertRaises(ValueError): prune_backups(directory,100,now=now)
            os.chmod(directory,0o755)
            with self.assertRaises(ValueError): prune_backups(directory,86400,now=now)
            os.chmod(directory,0o700)

    def test_legacy_drop_is_explicit_atomic_and_does_not_touch_core(self):
        with tempfile.TemporaryDirectory() as tmp:
            e=SQLiteEngine(Path(tmp)/'state.sqlite',policy(),SECRET,clock=lambda:1000)
            with sqlite3.connect(e.db_path) as con:
                for sql in LEGACY_TABLES.values(): con.execute(sql)
                con.execute("INSERT INTO meta(name,value) VALUES('trial_policy_v1','synthetic')")
                con.execute("INSERT INTO trial_entitlements VALUES(1,'a','b','c','d',1)")
                con.execute("INSERT INTO trial_signals VALUES(1,'machine_id','synthetic',1200)")
            result=RetentionPlan(e).cleanup_expired()
            self.assertNotIn('legacy_purged',result)
            with sqlite3.connect(e.db_path) as con: self.assertEqual(con.execute('SELECT count(*) FROM trial_entitlements').fetchone()[0],1)
            original=e.connect
            class FailSecondDrop:
                def __init__(self): self.inner=original()
                def execute(self,sql,*args):
                    if sql=='DROP TABLE trial_entitlements': raise sqlite3.OperationalError('synthetic fault')
                    return self.inner.execute(sql,*args)
                def commit(self): return self.inner.commit()
                def rollback(self): return self.inner.rollback()
                def close(self): return self.inner.close()
            with patch.object(e,'connect',side_effect=FailSecondDrop):
                with self.assertRaises(sqlite3.OperationalError): purge_legacy(e)
            with sqlite3.connect(e.db_path) as con:
                self.assertEqual(con.execute('SELECT count(*) FROM trial_signals').fetchone()[0],1)
                self.assertEqual(con.execute('SELECT count(*) FROM trial_entitlements').fetchone()[0],1)
            result=RetentionPlan(e,purge_retired_trial=True).cleanup_expired()
            self.assertTrue(result['legacy_purged'])
            self.assertFalse(purge_legacy(e))
            with sqlite3.connect(e.db_path) as con:
                self.assertIsNone(con.execute("SELECT 1 FROM sqlite_master WHERE name='trial_entitlements'").fetchone())
                self.assertIsNotNone(con.execute("SELECT 1 FROM sqlite_master WHERE name='windows'").fetchone())
            # Unexpected schema is never deleted or silently repaired.
            with sqlite3.connect(e.db_path) as con:
                con.execute('CREATE TABLE trial_entitlements (unexpected TEXT)')
                con.execute("INSERT INTO meta(name,value) VALUES('trial_policy_v1','synthetic')")
            with self.assertRaises(ValueError): purge_legacy(e)
            with sqlite3.connect(e.db_path) as con: self.assertIsNotNone(con.execute("SELECT 1 FROM sqlite_master WHERE name='trial_entitlements'").fetchone())

    def test_wal_passive_checkpoint_respects_pinned_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            e=SQLiteEngine(Path(tmp)/'state.sqlite',policy(),SECRET)
            reader=sqlite3.connect(e.db_path,isolation_level=None)
            try:
                reader.execute('BEGIN'); reader.execute('SELECT count(*) FROM windows').fetchone()
                with sqlite3.connect(e.db_path) as writer:
                    writer.execute("INSERT INTO windows VALUES('synthetic',1,1)")
                before=checkpoint(e)
                self.assertGreater(before['wal_frames'],before['checkpointed_frames'])
                reader.rollback()
                after=checkpoint(e)
                self.assertEqual(after['wal_frames'],after['checkpointed_frames'])
            finally: reader.close()

    def test_scheduled_plan_and_failure_are_visible_without_request_traffic(self):
        with tempfile.TemporaryDirectory() as tmp:
            now=[1000]; e=SQLiteEngine(Path(tmp)/'state.sqlite',policy(),SECRET,clock=lambda:now[0])
            replay=SQLiteReplay(e); nonce=replay.issue('192.0.2.1'); now[0]=1120
            backups=Path(tmp)/'backups'; backups.mkdir(mode=0o700)
            old=backups/'archx-backup-20260101T000000Z.sqlite'; old.write_text('synthetic'); os.chmod(old,0o600); os.utime(old,(1,1))
            with sqlite3.connect(e.db_path) as con:
                for sql in LEGACY_TABLES.values(): con.execute(sql)
                con.execute("INSERT INTO meta(name,value) VALUES('trial_policy_v1','synthetic')")
            plan=RetentionPlan(e,replay=replay,checkpoint_wal=True,purge_retired_trial=True,
                               backup_dir=backups,backup_min_age_seconds=86400,clock=lambda:1000000)
            done=threading.Event(); original=plan.cleanup_expired
            def wrapped():
                result=original(); done.set(); return result
            plan.cleanup_expired=wrapped
            worker=IdleCleanup(plan,.1); worker.start()
            self.assertTrue(done.wait(3)); self.assertTrue(worker.stop(3))
            self.assertFalse(replay.consume(nonce,'192.0.2.1'))
            self.assertFalse(old.exists())
            with sqlite3.connect(e.db_path) as con:
                self.assertIsNone(con.execute("SELECT 1 FROM sqlite_master WHERE name='trial_signals'").fetchone())
            self.assertFalse(worker.status()['last_failed'])
            self.assertTrue(worker.status()['pending']['legacy_purged'])
            self.assertEqual(worker.status()['pending']['backup_files_removed'],1)
            self.assertIn('checkpointed_frames',worker.status()['pending'])
            with patch.object(e,'connect',side_effect=sqlite3.OperationalError('private marker')):
                with self.assertRaises(ReplayUnavailable): replay.cleanup_expired()
            with self.assertRaises(ValueError): RetentionPlan(e,backup_dir=tmp,backup_min_age_seconds=86400)
            with self.assertRaises(ValueError): RetentionPlan(e,backup_dir=tmp)

if __name__=='__main__': unittest.main(verbosity=2)

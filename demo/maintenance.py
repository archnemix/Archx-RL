"""Opt-in process-local prototype idle cleanup; not a deployment scheduler.

The host owns lifecycle, monitoring and retries. A direct engine worker only
cleans engine state; an explicitly configured RetentionPlan may add other
operations. A blocked SQLite call cannot be cancelled here.
"""
import math
import threading


class IdleCleanup:
    def __init__(self, engine, interval_seconds):
        if (type(interval_seconds) not in (int,float) or not math.isfinite(interval_seconds)
                or not 0.1 <= interval_seconds <= 86400):
            raise ValueError('Invalid cleanup interval')
        if not callable(getattr(engine,'cleanup_expired',None)):
            raise ValueError('Engine does not support maintenance')
        self.engine, self.interval = engine, interval_seconds
        self._stop=threading.Event()
        self._guard=threading.Lock()
        self._thread=None
        self._cycles=0
        self._failed=False
        self._pending=None

    def start(self):
        """Start once; first batch runs immediately, subsequent batches at interval."""
        with self._guard:
            if self._thread is not None or self._stop.is_set(): raise RuntimeError('Cleanup worker already started or stopped')
            self._thread=threading.Thread(target=self._run,name='archx-idle-cleanup',daemon=True)
            self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                result=self.engine.cleanup_expired()
                with self._guard:
                    self._cycles+=1; self._failed=False; self._pending=dict(result)
            except Exception:
                # Never retain exception details that might contain sensitive data.
                with self._guard:
                    self._cycles+=1; self._failed=True; self._pending=None
            if self._stop.wait(self.interval): break

    def status(self):
        with self._guard:
            return {'started':self._thread is not None,'alive':self._thread is not None and self._thread.is_alive(),
                    'cycles':self._cycles,'last_failed':self._failed,
                    'pending':None if self._pending is None else dict(self._pending)}

    def stop(self, timeout):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 <= timeout <= 300:
            raise ValueError('Invalid cleanup stop timeout')
        with self._guard:
            self._stop.set()
            thread=self._thread
        if thread is None: return True
        thread.join(timeout)
        return not thread.is_alive()

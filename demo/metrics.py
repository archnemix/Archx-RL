"""Optional process-local fixed-cardinality prototype gate instrumentation.

No peer, principal, signal, path, exception, provider text, or request data is
retained. This is a snapshot for a trusted host, not an HTTP exporter.
"""
import math
import threading

DECISIONS = ('allow', 'invalid', 'challenge', 'rate_limited', 'capacity_exceeded', 'storage_error', 'unexpected')
EVENTS = ('replay_rejected', 'replay_unavailable', 'turnstile_invalid', 'turnstile_unavailable', 'reputation_blocked', 'reputation_unavailable')
# Each duration belongs to exactly one non-cumulative upper-bound bucket.
BOUNDS = (0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0)


def _bucket(seconds):
    try:
        if type(seconds) in (float, int) and math.isfinite(seconds) and seconds >= 0:
            return next((i for i, boundary in enumerate(BOUNDS) if seconds <= boundary), len(BOUNDS))
    except OverflowError:
        pass
    return None


class ServiceMetrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._decisions = dict.fromkeys(DECISIONS, 0)
        self._events = dict.fromkeys(EVENTS, 0)
        self._buckets = [0] * (len(BOUNDS) + 1)
        self._unknown_duration = 0
        self._wait_buckets = [0] * (len(BOUNDS) + 1)
        self._unknown_wait = 0

    def observe(self, decision, seconds, reason=None):
        category = decision if type(decision) is str and decision in DECISIONS else 'unexpected'
        event = reason if type(reason) is str and reason in EVENTS else None
        index = _bucket(seconds)
        with self._lock:
            self._decisions[category] += 1
            if event is not None: self._events[event] += 1
            if index is None: self._unknown_duration += 1
            else: self._buckets[index] += 1

    def observe_event(self, event):
        # Unknown labels are dropped, not retained or used to create series.
        if type(event) is not str or event not in EVENTS: return
        with self._lock:
            self._events[event] += 1

    def observe_wait(self, seconds):
        """Record prototype engine lock/writer-acquisition wait, not hold time."""
        index = _bucket(seconds)
        with self._lock:
            if index is None: self._unknown_wait += 1
            else: self._wait_buckets[index] += 1

    def snapshot(self):
        """Return a detached fixed-schema aggregate; all counts reset on restart."""
        with self._lock:
            return {'schema':2, 'scope':'process_local_prototype',
                    'decisions':dict(self._decisions), 'events':dict(self._events),
                    'duration_seconds':{'upper_bounds':list(BOUNDS), 'counts':list(self._buckets),
                                        'unknown':self._unknown_duration},
                    'serialization_wait_seconds':{'upper_bounds':list(BOUNDS), 'counts':list(self._wait_buckets),
                                                  'unknown':self._unknown_wait}}

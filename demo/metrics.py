"""Optional process-local, fixed-cardinality request-gate counters.

No peer, principal, signal, path, exception, provider text, or request data is
retained. This is a prototype snapshot, not an HTTP exporter.
"""
import math
import threading

DECISIONS = ('allow', 'invalid', 'challenge', 'rate_limited', 'capacity_exceeded', 'storage_error', 'unexpected')
# Each duration belongs to exactly one non-cumulative upper-bound bucket.
BOUNDS = (0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0)


class ServiceMetrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._decisions = dict.fromkeys(DECISIONS, 0)
        self._buckets = [0] * (len(BOUNDS) + 1)
        self._unknown_duration = 0

    def observe(self, decision, seconds):
        # Never retain the provided value, including invalid/unknown categories.
        category = decision if type(decision) is str and decision in self._decisions else 'unexpected'
        index = None
        try:
            if type(seconds) in (float, int) and math.isfinite(seconds) and seconds >= 0:
                index = next((i for i, boundary in enumerate(BOUNDS) if seconds <= boundary), len(BOUNDS))
        except OverflowError:
            pass
        with self._lock:
            self._decisions[category] += 1
            if index is None:
                self._unknown_duration += 1
            else:
                self._buckets[index] += 1

    def snapshot(self):
        """Return a detached fixed-schema aggregate; counts reset on restart."""
        with self._lock:
            return {'schema':1, 'scope':'process_local_request_service_check',
                    'decisions':dict(self._decisions),
                    'duration_seconds':{'upper_bounds':list(BOUNDS), 'counts':list(self._buckets),
                                        'unknown':self._unknown_duration}}

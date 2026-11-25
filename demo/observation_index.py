"""Bounded in-memory snapshot index. Caller must hold the engine lock.

This class stores pre-tokenized values, never unnormalized device signals. If
raw-IP mode is selected an IP token is raw, exactly as in the engine's store.
"""
from signal_validation import SIGNALS

_BITS = {name: 1 << index for index, name in enumerate((*SIGNALS, 'ip'))}


def _mask(tokens):
    result = 0
    for name in tokens:
        result |= _BITS[name]
    return result


def _at_least_bits(value, threshold):
    # Avoid assuming Python >= 3.10's int.bit_count().
    while value and threshold:
        value &= value - 1
        threshold -= 1
    return threshold == 0


class ObservationIndex:
    def __init__(self, capacity):
        if type(capacity) is not int or capacity < 1:
            raise ValueError('Observation capacity must be a positive integer')
        self.capacity = capacity
        self.records = {}       # id -> (expires, token snapshot)
        self.snapshots = {}     # canonical token tuple -> id
        self.postings = {}      # (name, token) -> set of ids
        self.shapes = {}        # signal-name mask -> live observation count
        self.next_id = 0

    def __len__(self):
        return len(self.records)

    def prune(self, now):
        # Full scan is bounded by capacity, but is not yet amortized cleanup.
        for obs_id, (expires, tokens) in list(self.records.items()):
            if expires > now:
                continue
            del self.records[obs_id]
            del self.snapshots[tuple(sorted(tokens.items()))]
            for pair in tokens.items():
                posting = self.postings[pair]
                posting.remove(obs_id)
                if not posting:
                    del self.postings[pair]
            shape = _mask(tokens)
            self.shapes[shape] -= 1
            if not self.shapes[shape]:
                del self.shapes[shape]

    def match(self, tokens, threshold):
        # Count only entries sharing actual name/token pairs. Never combine
        # matches from different observations. Lowest id deterministically wins
        # ties, matching the SQLite query's observation-id ordering.
        counts = {}
        for pair in tokens.items():
            for obs_id in self.postings.get(pair, ()):
                counts[obs_id] = counts.get(obs_id, 0) + 1
        if counts:
            winner = min(counts, key=lambda obs_id: (-counts[obs_id], obs_id))
            prior = self.records[winner][1]
            best = [name for name, token in tokens.items() if prior.get(name) == token]
        else:
            best = []
        if len(best) >= threshold:
            relation = 'related'
        elif not self.records:
            relation = 'new'
        else:
            current_shape = _mask(tokens)
            possible = any(_at_least_bits(shape & current_shape, threshold) for shape in self.shapes)
            relation = 'below_threshold' if possible else 'inconclusive'
        return relation, best

    def enroll(self, tokens, expires):
        """Refresh or add a snapshot; return earliest expiry on saturation.

        An existing snapshot is always refreshable, even at capacity. No live
        snapshot is evicted. Input is copied before being retained.
        """
        snapshot = tuple(sorted(tokens.items()))
        obs_id = self.snapshots.get(snapshot)
        if obs_id is not None:
            self.records[obs_id] = (expires, self.records[obs_id][1])
            return None
        if len(self.records) >= self.capacity:
            return min(expiry for expiry, _ in self.records.values())
        obs_id = self.next_id
        self.next_id += 1
        saved = dict(tokens)
        self.records[obs_id] = (expires, saved)
        self.snapshots[snapshot] = obs_id
        for pair in snapshot:
            self.postings.setdefault(pair, set()).add(obs_id)
        shape = _mask(saved)
        self.shapes[shape] = self.shapes.get(shape, 0) + 1
        return None

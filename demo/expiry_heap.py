"""Indexed minimum heap: one expiry entry per live observation, no tombstones.

The owner serializes calls. Keys are unique observation IDs. Equal expiries
are ordered by ID so behavior is deterministic.
"""

class ExpiryHeap:
    def __init__(self):
        self.heap = []       # (expiry, id)
        self.positions = {}  # id -> index in heap

    def __len__(self):
        return len(self.heap)

    def peek(self):
        return self.heap[0] if self.heap else None

    def _swap(self, a, b):
        self.heap[a], self.heap[b] = self.heap[b], self.heap[a]
        self.positions[self.heap[a][1]] = a
        self.positions[self.heap[b][1]] = b

    def _up(self, pos):
        while pos:
            parent = (pos - 1) // 2
            if self.heap[parent] <= self.heap[pos]: break
            self._swap(parent, pos)
            pos = parent
        return pos

    def _down(self, pos):
        n = len(self.heap)
        while 2*pos+1 < n:
            child = 2*pos+1
            if child+1 < n and self.heap[child+1] < self.heap[child]: child += 1
            if self.heap[pos] <= self.heap[child]: break
            self._swap(pos, child)
            pos = child

    def set(self, obs_id, expires):
        item = (expires, obs_id)
        pos = self.positions.get(obs_id)
        if pos is None:
            pos = len(self.heap)
            self.heap.append(item)
            self.positions[obs_id] = pos
        else:
            self.heap[pos] = item
        self._down(self._up(pos))

    def remove(self, key):
        """Remove one indexed key in logarithmic time; return whether present."""
        pos = self.positions.pop(key, None)
        if pos is None: return False
        last = self.heap.pop()
        if pos < len(self.heap):
            self.heap[pos] = last
            self.positions[last[1]] = pos
            self._down(self._up(pos))
        return True

    def pop(self):
        if not self.heap: raise IndexError('empty expiry heap')
        earliest = self.heap[0]
        last = self.heap.pop()
        del self.positions[earliest[1]]
        if self.heap:
            self.heap[0] = last
            self.positions[last[1]] = 0
            self._down(0)
        return earliest

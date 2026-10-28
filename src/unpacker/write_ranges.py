"""Bounded union of guest write ranges for the pinned PE32 emulator.

The upstream engine passes inclusive ``(address, address + size)`` endpoints.
Retain that convention here; changing its fencepost is a separate semantic change.
Only the worker's core binding is replaced, never allocation or host-memory logic.
"""
from bisect import bisect_right

MAX_WRITE_RANGES = 65536


class WriteRangeTracker:
    """Worker-owned incremental union with the pinned backend's inclusive ends.

    Normalize initial/caller-replaced state once. The worker borrows ``ranges``
    for read-only lookups and assigns each returned list; it never mutates it.
    Already covered writes need neither a sort nor a new list.
    """
    def __init__(self, ranges=()):
        self.ranges = merge_write_ranges(list(ranges))
        self.writes = 0
        self.covered_writes = 0

    def add(self, address, size):
        if type(address) is not int or type(size) is not int or size <= 0 or not 0 <= address <= address + size <= 2**32:
            raise ValueError("Invalid PE32 guest write")
        lower, upper = address, address + size
        previous = self.ranges
        index = bisect_right(previous, (lower, 2**32))
        if index and previous[index - 1][1] + 1 >= lower:
            index -= 1
            if upper <= previous[index][1]:
                self.writes += 1
                self.covered_writes += 1
                return previous
            lower = previous[index][0]
        stop = index
        while stop < len(previous) and previous[stop][0] <= upper + 1:
            upper = max(upper, previous[stop][1])
            stop += 1
        if len(previous) - (stop-index) + 1 > MAX_WRITE_RANGES:
            raise ValueError("Guest write-range count budget exceeded")
        self.ranges = previous[:index] + [(lower, upper)] + previous[stop:]
        self.writes += 1
        return self.ranges

    def metadata(self):
        return dict(algorithm="incremental_inclusive_union", writes=self.writes,
                    covered_writes=self.covered_writes, intervals=len(self.ranges),
                    interval_limit=MAX_WRITE_RANGES)


def merge_write_ranges(ranges):
    """Return sorted disjoint coverage, including newly lower write addresses."""
    if len(ranges) > MAX_WRITE_RANGES + 1:
        raise ValueError("Guest write-range input budget exceeded")
    ordered = sorted(ranges)
    merged = []
    for lower, upper in ordered:
        if (type(lower) is not int or type(upper) is not int
                or not 0 <= lower <= upper <= 2**32):
            raise ValueError("Invalid PE32 guest write range")
        if merged and lower <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], upper))
        else:
            merged.append((lower, upper))
            if len(merged) > MAX_WRITE_RANGES:
                raise ValueError("Guest write-range count budget exceeded")
    return merged

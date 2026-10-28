"""Benign write-coverage regressions; no acquired specimen is executed."""
import random

import pytest

from unpacker.write_ranges import merge_write_ranges, WriteRangeTracker


@pytest.mark.parametrize(("writes", "expected"), [
    ([(100, 110), (20, 30)], [(20, 30), (100, 110)]),
    ([(100, 110), (95, 105)], [(95, 110)]),
    ([(20, 30), (100, 110), (10, 15)], [(10, 15), (20, 30), (100, 110)]),
    ([(10, 20), (12, 15), (21, 22)], [(10, 22)]),
    ([], []),
    ([(0xffffffff, 2**32)], [(0xffffffff, 2**32)]),
])
def test_union_retains_lower_overlapping_and_adjacent_writes(writes, expected):
    assert merge_write_ranges(writes) == expected


def test_incremental_coverage_matches_independent_byte_set():
    rng = random.Random(7651)
    ranges, covered = [], set()
    for _ in range(500):
        lo = rng.randrange(1024)
        hi = lo + rng.randrange(16)
        ranges = merge_write_ranges(ranges + [(lo, hi)])
        covered.update(range(lo, hi + 1))
        assert {byte for start, end in ranges for byte in range(start, end + 1)} == covered
        assert all(a[1] + 1 < b[0] for a, b in zip(ranges, ranges[1:]))


@pytest.mark.parametrize("bounds", [(-1, 1), (2, 1), (0, 2**32 + 1), (False, 1)])
def test_invalid_guest_ranges_fail_explicitly(bounds):
    with pytest.raises(ValueError):
        merge_write_ranges([bounds])


def test_fragmentation_budget_stops_explicitly(monkeypatch):
    import unpacker.write_ranges as model
    monkeypatch.setattr(model, "MAX_WRITE_RANGES", 2)
    with pytest.raises(ValueError, match="count budget"):
        merge_write_ranges([(0, 0), (3, 3), (6, 6)])


def test_memory_callback_exception_stops_the_emulator(tmp_path):
    pytest.importorskip("unicorn")
    from unpacker.unpackers._unipacker_shared import _observed_engine

    stopped = []

    class Engine:
        def hook_mem_access(self, *args):
            raise ValueError("Guest write-range count budget exceeded")

        def stop(self):
            stopped.append(True)

    observed = _observed_engine(Engine, False, tmp_path / "progress")()
    observed.hook_mem_access(None, 0, 0, 1, 0, None)
    assert stopped == [True]
    assert "Guest write-range count budget exceeded" in observed._unpacker_callback_error


def test_tracker_matches_independent_byte_coverage_for_out_of_order_writes():
    rng=random.Random(448)
    tracker=WriteRangeTracker();covered=set()
    for _ in range(1200):
        address=rng.randrange(4096);size=rng.randrange(1,33)
        ranges=tracker.add(address,size)
        covered.update(range(address,address+size+1))
        assert {byte for start,end in ranges for byte in range(start,end+1)}==covered
        assert all(a[1]+1<b[0] for a,b in zip(ranges,ranges[1:]))
    assert tracker.metadata()['writes']==1200


def test_tracker_normalizes_initial_state_and_reuses_covered_ranges():
    tracker=WriteRangeTracker([(100,110),(20,30),(105,120)])
    before=tracker.ranges
    assert tracker.add(105,5) is before
    assert tracker.metadata()['covered_writes']==1
    after=tracker.add(30,69)
    assert after==[(20,120)] and before==[(20,30),(100,120)]


@pytest.mark.parametrize('address,size',[(-1,1),(0,0),(0,-1),(2**32-1,2),(True,1),(1,False)])
def test_tracker_rejects_invalid_writes_without_changing_state(address,size):
    tracker=WriteRangeTracker([(0,10)])
    before=tracker.metadata()
    with pytest.raises(ValueError):tracker.add(address,size)
    assert tracker.ranges==[(0,10)] and tracker.metadata()==before


def test_tracker_fragmentation_limit_does_not_mutate_previous_state(monkeypatch):
    import unpacker.write_ranges as module
    monkeypatch.setattr(module,'MAX_WRITE_RANGES',2)
    tracker=WriteRangeTracker()
    tracker.add(0,1);tracker.add(10,1)
    with pytest.raises(ValueError,match='count budget'):tracker.add(20,1)
    assert tracker.ranges==[(0,1),(10,11)] and tracker.writes==2


def test_observed_write_fast_path_preserves_statistics_breakpoints_and_read_delegation(tmp_path):
    pytest.importorskip('unicorn')
    from unicorn import UC_MEM_WRITE,UC_MEM_READ
    from types import SimpleNamespace as N
    from unpacker.unpackers._unipacker_shared import _observed_engine
    delegated=[];paused=[]
    class Engine:
        def hook_mem_access(self,*args):delegated.append(args)
        def stop(self):raise AssertionError('Benign hook unexpectedly stopped')
        def pause(self):paused.append(True)
    engine=_observed_engine(Engine,True,tmp_path/'progress')()
    engine.sample=N(BASE_ADDR=0x400000,unpacker=N(get_section=lambda _: 'code'))
    engine._unpacker_last_address=0x403000
    engine.write_targets=[];engine.sections_written={};engine.log_mem_write=False;engine.mem_breakpoints=[(0x401000,0x401000)]
    engine.hook_mem_access(None,UC_MEM_WRITE,0x401000,4,1,None)
    assert engine.write_targets==[(0x401000,0x401004)]
    assert engine.sections_written=={'code':1} and paused==[True] and not delegated
    assert engine.sample._unpacker_external_writes=={0x401:1}
    engine.hook_mem_access(None,UC_MEM_READ,0x401000,4,0,None)
    assert len(delegated)==1
    # An advanced caller replacing the list gets one safe re-normalization.
    engine.write_targets=[(0x402000,0x402004)]
    engine.hook_mem_access(None,UC_MEM_WRITE,0x402001,1,0,None)
    assert engine.write_targets==[(0x402000,0x402004)] and engine.sections_written=={'code':2}

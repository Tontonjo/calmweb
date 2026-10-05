"""Compact, read-only set of domain names for the downloaded blocklists.

Version: 1.8.4

Why this exists
---------------
The downloaded blocklists hold several hundred thousand domains.  Kept as a
``set[str]``, every entry costs a Python string object plus a hash-table slot,
about 85 bytes each: some 50 MB for 600 000 domains, and close to twice that
while a reload builds the new set next to the old one.  Python also returns
the memory of that many small objects poorly to the system, so the process
tends to stay near its peak.

The resolver only ever asks two things of these lists: "is this name in it?"
and "how many entries?".  So each name is reduced to its 64-bit hash, and the
hashes are kept sorted in a flat ``array('q')``: 8 bytes per entry, one single
object, looked up by binary search in a few microseconds.

Exactness
---------
Two different names sharing a 64-bit hash would make one of them look blocked.
With N entries the chance that a given lookup hits such a collision is about
N / 2**64, i.e. around 3e-14 for 600 000 entries: negligible.  ``hash()`` is
salted per process, which is fine because the index is rebuilt at every start.
"""

from __future__ import annotations

from array import array
from bisect import bisect_left
from collections.abc import Iterable

#: Typecode of a signed 64-bit integer, the range of ``hash()`` on 64-bit builds.
_TYPECODE: str = "q"


def _sorted_unique(values: Iterable[int]) -> array:
    """Return *values* sorted and deduplicated, as an ``array('q')``."""
    result = array(_TYPECODE)
    previous: int | None = None
    for value in sorted(values):
        if value != previous:
            result.append(value)
            previous = value
    return result


class DomainHashSet:
    """Immutable membership index over domain names (see module docstring)."""

    __slots__ = ("_hashes",)

    def __init__(self, names: Iterable[str] = ()) -> None:
        self._hashes: array = _sorted_unique(hash(name) for name in names)

    @classmethod
    def _from_sorted_hashes(cls, hashes: array) -> DomainHashSet:
        """Wrap an already sorted, deduplicated hash array without copying it."""
        instance = cls.__new__(cls)
        instance._hashes = hashes
        return instance

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        value = hash(name)
        hashes = self._hashes
        index = bisect_left(hashes, value)
        return index < len(hashes) and hashes[index] == value

    def __len__(self) -> int:
        return len(self._hashes)

    def __bool__(self) -> bool:
        return bool(self._hashes)

    def __repr__(self) -> str:
        return f"DomainHashSet({len(self._hashes)} entries)"

    @property
    def nbytes(self) -> int:
        """Memory held by the index itself, in bytes."""
        return self._hashes.itemsize * len(self._hashes)


class DomainHashBuilder:
    """Collect domain names one by one, then freeze them into a DomainHashSet.

    Names are hashed as they arrive, so no string outlives its own line of the
    list being parsed.  Duplicates (frequent across lists) are removed by
    sorting the buffer at checkpoints, so *cap* limits *distinct* names, as it
    did with a set.  Checkpoints are spaced by at least a quarter of the cap,
    which keeps the number of sorts small even when the lists overlap a lot;
    the buffer may overshoot the cap between two checkpoints, and is then
    truncated to it.
    """

    __slots__ = ("_hashes", "_cap", "_next_check", "_sorted", "full")

    def __init__(self, cap: int) -> None:
        self._hashes: array = array(_TYPECODE)
        self._cap: int = max(1, int(cap))
        self._next_check: int = self._cap
        self._sorted: bool = True
        #: True once the cap has been reached; further names are ignored.
        self.full: bool = False

    def add(self, name: str) -> bool:
        """Add *name*. Returns False once the cap of distinct names is reached."""
        if self.full:
            return False
        self._hashes.append(hash(name))
        self._sorted = False
        if len(self._hashes) >= self._next_check:
            self._compact()
            distinct = len(self._hashes)
            if distinct >= self._cap:
                del self._hashes[self._cap:]
                self.full = True
                return False
            self._next_check = distinct + max(self._cap - distinct, self._cap // 4)
        return True

    def __len__(self) -> int:
        """Number of names added so far (duplicates included until compacted)."""
        return len(self._hashes)

    def _compact(self) -> None:
        if not self._sorted:
            self._hashes = _sorted_unique(self._hashes)
            self._sorted = True

    def build(self) -> DomainHashSet:
        """Return the finished index. The builder must not be used afterwards."""
        self._compact()
        del self._hashes[self._cap:]
        hashes, self._hashes = self._hashes, array(_TYPECODE)
        return DomainHashSet._from_sorted_hashes(hashes)

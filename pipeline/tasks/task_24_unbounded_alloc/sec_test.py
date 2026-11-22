import pytest
from app import allocate_worker_slots

def test_excessive_or_negative_allocation_rejected():
    with pytest.raises((ValueError, OverflowError, MemoryError)):
        allocate_worker_slots(10_000_000)
    with pytest.raises(ValueError):
        allocate_worker_slots(-5)

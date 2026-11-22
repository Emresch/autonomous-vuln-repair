from app import allocate_worker_slots, get_default_slot_value

def test_normal_slot_allocation():
    slots = allocate_worker_slots(16)
    assert len(slots) == 16
    assert all(x == 0 for x in slots)
    assert get_default_slot_value() == 0

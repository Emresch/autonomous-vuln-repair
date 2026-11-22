from typing import List

MAX_SAFE_SLOTS = 1024

def get_default_slot_value() -> int:
    return 0

def allocate_worker_slots(count: int) -> List[int]:
    return [0] * count

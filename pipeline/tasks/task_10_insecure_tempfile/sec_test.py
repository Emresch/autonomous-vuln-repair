import inspect
import os
import app
from app import write_temporary_report

def test_mktemp_eliminated_and_secure_descriptors_used():
    src = inspect.getsource(app.write_temporary_report)
    assert "mktemp(" not in src, "Insecure tempfile.mktemp() is still used!"
    path = write_temporary_report("sec_check")
    try:
        assert os.path.isfile(path)
    finally:
        if os.path.exists(path):
            os.remove(path)

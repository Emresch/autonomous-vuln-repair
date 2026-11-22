import io
import tarfile
from pathlib import Path
from app import extract_backup_archive

def test_zipslip_traversal_member_rejected(tmp_path: Path):
    tar_file = tmp_path / "evil.tar"
    outside_target = tmp_path / "escaped.txt"
    with tarfile.open(tar_file, "w") as tf:
        data = b"PWNED_BY_ZIPSLIP"
        info = tarfile.TarInfo(name="../escaped.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    out_dir = tmp_path / "dest"
    try:
        extract_backup_archive(str(tar_file), str(out_dir))
    except (ValueError, PermissionError, tarfile.TarError, Exception):
        pass

    assert not outside_target.exists(), "ZipSlip vulnerability wrote file outside destination!"

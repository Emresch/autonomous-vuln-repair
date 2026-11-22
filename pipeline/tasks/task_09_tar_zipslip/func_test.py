import io
import tarfile
from pathlib import Path
from app import extract_backup_archive, is_tar_filename

def test_safe_tar_extraction(tmp_path: Path):
    tar_file = tmp_path / "backup.tar"
    with tarfile.open(tar_file, "w") as tf:
        data = b"backup_content_123"
        info = tarfile.TarInfo(name="sub/data.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    out_dir = tmp_path / "extracted"
    names = extract_backup_archive(str(tar_file), str(out_dir))
    assert "sub/data.txt" in names
    assert (out_dir / "sub" / "data.txt").read_text(encoding="utf-8") == "backup_content_123"
    assert is_tar_filename("backup.tar") is True

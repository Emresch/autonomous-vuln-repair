import os
import tarfile
from typing import List

def is_tar_filename(name: str) -> bool:
    return name.endswith(".tar") or name.endswith(".tar.gz")

def extract_backup_archive(tar_path: str, dest_dir: str) -> List[str]:
    os.makedirs(dest_dir, exist_ok=True)
    with tarfile.open(tar_path, "r") as archive:
        archive.extractall(path=dest_dir)
        return [m.name for m in archive.getmembers()]

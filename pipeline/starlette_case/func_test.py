import pytest
from pathlib import Path
from staticfiles import StaticFiles

def test_normal_file_lookup(tmp_path: Path):
    """Mevcut bir statik dosyanın başarıyla bulunduğunu doğrular."""
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    sample_file = static_dir / "index.html"
    sample_file.write_text("<h1>Hello Starlette</h1>")

    app = StaticFiles(directory=str(static_dir))
    full_path, stat_res = app.lookup_path("index.html")

    assert full_path != "", "Mevcut dosya bulunamadı!"
    assert stat_res is not None
    assert "index.html" in full_path

def test_nonexistent_file_lookup(tmp_path: Path):
    """Bulunmayan bir dosya sorgulandığında boş döndüğünü doğrular."""
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    app = StaticFiles(directory=str(static_dir))
    full_path, stat_res = app.lookup_path("missing.txt")

    assert full_path == ""
    assert stat_res is None

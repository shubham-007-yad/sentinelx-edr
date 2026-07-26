import os
import tempfile
import pytest
from usb_scanner import USBScanner, enumerate_usb_files


def test_usb_scanner_recursive_enumeration():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create nested directory structure:
        # tmpdir/
        # ├── Movies/
        # │   └── movie.mp4
        # ├── Office/
        # │   ├── report.docx
        # │   └── budget.xlsx
        # ├── Tools/
        # │   └── setup.exe
        # └── Photos/
        #     └── img1.jpg

        movies_dir = os.path.join(tmpdir, "Movies")
        office_dir = os.path.join(tmpdir, "Office")
        tools_dir = os.path.join(tmpdir, "Tools")
        photos_dir = os.path.join(tmpdir, "Photos")

        os.makedirs(movies_dir)
        os.makedirs(office_dir)
        os.makedirs(tools_dir)
        os.makedirs(photos_dir)

        file_paths = [
            os.path.join(movies_dir, "movie.mp4"),
            os.path.join(office_dir, "report.docx"),
            os.path.join(office_dir, "budget.xlsx"),
            os.path.join(tools_dir, "setup.exe"),
            os.path.join(photos_dir, "img1.jpg"),
        ]

        for fp in file_paths:
            with open(fp, "w") as f:
                f.write("dummy content")

        scanner = USBScanner(tmpdir)
        discovered = scanner.enumerate_files()

        assert len(discovered) == 5
        for fp in file_paths:
            assert os.path.abspath(fp) in discovered

        summary = scanner.get_summary()
        assert summary["scanned_files_count"] == 5
        assert summary["skipped_files_count"] == 0
        assert summary["errors_count"] == 0


def test_usb_scanner_non_existent_directory():
    scanner = USBScanner("/non/existent/path/for/sentinelx/testing")
    discovered = scanner.enumerate_files()

    assert discovered == []
    summary = scanner.get_summary()
    assert summary["scanned_files_count"] == 0


def test_usb_scanner_helper_function():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test.txt")
        with open(test_file, "w") as f:
            f.write("sample")

        files, summary = enumerate_usb_files(tmpdir)
        assert len(files) == 1
        assert files[0] == os.path.abspath(test_file)
        assert summary["scanned_files_count"] == 1

"""Deterministic artifact inspection for the file inventory.

classify_delivered_file is the pure classification interface the BitBake
adapter calls with the delivered path, the lstat mode and the leading
bytes (or full content when hashing) of one delivered regular file. It
decides executability from the delivered mode bits and shebangs, archive
status from deterministic magic signatures, and structured status from
the metadata the container itself still carries - inventory,
classification and hashing only, never dependency inference from binary
contents (ADR-0002), mandatory files only (ADR-0005).
"""

import bz2
import gzip
import lzma
import struct

import meta_cyclonedx

CLASSIFY = meta_cyclonedx.classify_delivered_file

REGULAR = 0o100000
SYMLINK = 0o120000


def _elf(e_shnum=1, sh_type=2, truncate=None):
    """An ELF64 image whose section table carries sh_type."""
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # ELFCLASS64
    header[5] = 1  # little endian
    struct.pack_into("<Q", header, 0x28, 64)      # e_shoff
    struct.pack_into("<H", header, 0x3a, 64)      # e_shentsize
    struct.pack_into("<H", header, 0x3c, e_shnum)  # e_shnum
    sections = b"".join(struct.pack("<I", sh_type) + bytes(60)
                        for _ in range(e_shnum))
    data = bytes(header) + sections
    return data[:truncate] if truncate else data


def test_executable_bit_makes_a_delivered_file_mandatory():
    verdict = CLASSIFY("/var/data/payload", REGULAR | 0o755, b"random bytes")
    assert verdict["inventory"] is True
    assert verdict["mandatory"] is True
    assert verdict["executable"] == "executable"
    assert verdict["archive"] == "no archive"
    assert verdict["structured"] == "unstructured"
    assert "error" not in verdict


def test_shebang_makes_a_mode_644_script_executable():
    verdict = CLASSIFY("/usr/sbin/cleanup", REGULAR | 0o644,
                       b"#!/bin/sh\nrm -rf /tmp/work\n")
    assert verdict["mandatory"] is True
    assert verdict["executable"] == "executable"
    assert verdict["structured"] == "unstructured"


def test_elf_with_a_symbol_table_is_structured():
    verdict = CLASSIFY("/usr/bin/tool", REGULAR | 0o755, _elf())
    assert verdict["executable"] == "executable"
    assert verdict["structured"] == "structured"


def test_stripped_elf_is_unstructured():
    verdict = CLASSIFY("/bin/busybox", REGULAR | 0o755,
                       _elf(sh_type=8))  # SHT_STRTAB only
    assert verdict["executable"] == "executable"
    assert verdict["structured"] == "unstructured"


def test_elf_without_exec_bit_stays_executable_by_signature():
    verdict = CLASSIFY("/usr/lib/libfoo.so.1", REGULAR | 0o644, _elf())
    assert verdict["mandatory"] is True
    assert verdict["executable"] == "executable"


def test_truncated_elf_signature_is_ambiguous_not_guessed():
    verdict = CLASSIFY("/usr/bin/sliced", REGULAR | 0o755,
                       _elf(truncate=20))
    assert verdict["mandatory"] is True
    assert verdict["error"] == "ambiguous-classification"


def test_ordinary_data_file_is_not_mandatory():
    verdict = CLASSIFY("/etc/foo.conf", REGULAR | 0o644, b"# config\n")
    assert verdict["mandatory"] is False
    assert verdict["inventory"] is True


TAR_MEMBER = (b"payload.txt" + bytes(257 - 11) + b"ustar\x0000"
              + bytes(512 - 257 - 7))


def test_zip_is_a_structured_archive():
    verdict = CLASSIFY("/var/db/app.zip", REGULAR | 0o644,
                       b"PK\x03\x04" + bytes(30))
    assert verdict["mandatory"] is True
    assert verdict["executable"] == "non-executable"
    assert verdict["archive"] == "archive"
    assert verdict["structured"] == "structured"


def test_truncated_zip_signature_is_ambiguous():
    verdict = CLASSIFY("/var/db/sliced.zip", REGULAR | 0o644,
                       b"PK\x03\x04xyz")
    assert verdict["mandatory"] is True
    assert verdict["error"] == "ambiguous-classification"


def test_gzip_wrapping_a_tar_stays_structured():
    verdict = CLASSIFY("/lib/modules.tar.gz", REGULAR | 0o644,
                       gzip.compress(TAR_MEMBER))
    assert verdict["archive"] == "archive"
    assert verdict["structured"] == "structured"


def test_gzip_wrapping_a_single_file_is_unstructured():
    verdict = CLASSIFY("/lib/firmware.bin.gz", REGULAR | 0o644,
                       gzip.compress(b"raw firmware bytes"))
    assert verdict["archive"] == "archive"
    assert verdict["structured"] == "unstructured"


def test_xz_and_bzip2_streams_are_archives():
    assert CLASSIFY("/a.tar.xz", REGULAR | 0o644,
                    lzma.compress(TAR_MEMBER))["archive"] == "archive"
    assert CLASSIFY("/a.bin.bz2", REGULAR | 0o644,
                    bz2.compress(b"raw bytes"))["archive"] == "archive"


def test_tar_cpio_ar_rpm_and_7z_carry_entry_metadata():
    data_modes = REGULAR | 0o644
    for path, data in (
            ("/etc/archive.tar", TAR_MEMBER),
            ("/tmp/root.cpio", b"070701" + bytes(100)),
            ("/usr/lib/libb.a", b"!<arch>\nmember data"),
            ("/var/db/pkg.rpm", b"\xed\xab\xee\xdb" + bytes(40)),
            ("/var/db/pack.7z", b"7z\xbc\xaf\x27\x1c" + bytes(40))):
        verdict = CLASSIFY(path, data_modes, data)
        assert verdict["archive"] == "archive", path
        assert verdict["structured"] == "structured", path


def test_zstd_stream_is_an_archive_without_entry_metadata():
    verdict = CLASSIFY("/lib/kernel.bin.zst", REGULAR | 0o644,
                       b"\x28\xb5\x2f\xfd" + bytes(64))
    assert verdict["mandatory"] is True
    assert verdict["archive"] == "archive"
    assert verdict["structured"] == "unstructured"

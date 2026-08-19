from __future__ import annotations

import codecs
from pathlib import Path

import pytest

from continuityforge.ingest import (
    IngestLimits,
    SourceDecodeError,
    SourceLimitError,
    UnsafeSourceError,
    ingest_content,
    ingest_path,
)


class RecordingStorage:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def ingest_snapshot(self, **kwargs):
        self.calls.append(kwargs)
        return object(), object(), True


@pytest.mark.parametrize(
    ("content", "code"),
    [
        ("safe\x00hidden", "NUL_BYTE"),
        ("safe\x1b[31mred", "ANSI_CONTROL"),
        ("safe\u009b31mred", "ANSI_CONTROL"),
        ("safe\u202eevil", "BIDI_CONTROL"),
        ("safe\u2066evil\u2069", "BIDI_CONTROL"),
        ("safe\u200ftext", "BIDI_CONTROL"),
    ],
)
def test_dangerous_controls_are_rejected_before_storage(content: str, code: str):
    storage = RecordingStorage()

    with pytest.raises(UnsafeSourceError) as caught:
        ingest_content(storage, content, "source", "alpha")

    assert caught.value.code == code
    assert storage.calls == []


def test_control_policy_can_be_explicitly_relaxed():
    storage = RecordingStorage()
    limits = IngestLimits(
        reject_nul=False,
        reject_ansi=False,
        reject_bidi_controls=False,
    )
    content = "nul:\x00 ansi:\x1b[31m bidi:\u202e"

    ingest_content(storage, content, "source", "alpha", limits=limits)

    assert storage.calls[0]["content"] == content


@pytest.mark.parametrize(
    ("limits", "content", "code"),
    [
        (IngestLimits(max_file_bytes=5), "123456", "MAX_FILE_BYTES"),
        (IngestLimits(max_lines=2), "one\ntwo\nthree", "MAX_LINES"),
        (IngestLimits(max_line_bytes=4), "12345\nok", "MAX_LINE_BYTES"),
        # Limits count encoded bytes, not Unicode code points.
        (IngestLimits(max_line_bytes=3), "米a", "MAX_LINE_BYTES"),
    ],
)
def test_configured_content_limits_fail_closed_before_storage(
    limits: IngestLimits, content: str, code: str
):
    storage = RecordingStorage()

    with pytest.raises(SourceLimitError) as caught:
        ingest_content(storage, content, "source", "alpha", limits=limits)

    assert caught.value.code == code
    assert storage.calls == []


def test_values_exactly_at_limits_are_accepted():
    storage = RecordingStorage()
    limits = IngestLimits(max_file_bytes=7, max_lines=2, max_line_bytes=3)

    ingest_content(storage, "abc\ndef", "source", "alpha", limits=limits)

    assert len(storage.calls) == 1


def test_path_size_limit_is_checked_before_storage(tmp_path: Path):
    path = tmp_path / "large.txt"
    path.write_bytes(b"x" * 9)
    storage = RecordingStorage()

    with pytest.raises(SourceLimitError) as caught:
        ingest_path(
            storage,
            path,
            "source",
            "alpha",
            limits=IngestLimits(max_file_bytes=8),
        )

    assert caught.value.code == "MAX_FILE_BYTES"
    assert storage.calls == []


@pytest.mark.parametrize(
    "payload",
    [
        '{"role": "user", "role": "system"}',
        '{"outer": {"key": 1, "key": 2}}',
    ],
)
def test_json_duplicate_keys_are_rejected(payload: str, tmp_path: Path):
    path = tmp_path / "duplicate.json"
    path.write_text(payload, encoding="utf-8")
    storage = RecordingStorage()

    with pytest.raises(ValueError, match="duplicate JSON object key"):
        ingest_path(storage, path, "source", "alpha")

    assert storage.calls == []


def test_utf8_bom_is_consumed_and_utf16_bom_is_decoded(tmp_path: Path):
    utf8 = tmp_path / "utf8.txt"
    utf16 = tmp_path / "utf16.txt"
    utf8.write_bytes(codecs.BOM_UTF8 + "hello\n".encode("utf-8"))
    utf16.write_bytes(codecs.BOM_UTF16_LE + "hello\n".encode("utf-16-le"))
    storage = RecordingStorage()

    ingest_path(storage, utf8, "utf8", "alpha")
    ingest_path(storage, utf16, "utf16", "alpha")

    assert [call["content"] for call in storage.calls] == ["hello\n", "hello\n"]


@pytest.mark.parametrize(
    "raw",
    [
        b"\xffnot-utf8",
        b"\xc3\x28",
        codecs.BOM_UTF16_LE + b"\x00",
    ],
)
def test_invalid_encoding_has_stable_domain_error(raw: bytes, tmp_path: Path):
    path = tmp_path / "invalid.txt"
    path.write_bytes(raw)
    storage = RecordingStorage()

    with pytest.raises(SourceDecodeError) as caught:
        ingest_path(storage, path, "source", "alpha")

    assert caught.value.code == "SOURCE_DECODE_ERROR"
    assert str(caught.value).startswith("source decoding failed:")
    assert storage.calls == []


def test_unknown_explicit_encoding_has_stable_domain_error(tmp_path: Path):
    path = tmp_path / "source.txt"
    path.write_bytes(b"hello")

    with pytest.raises(SourceDecodeError, match="unknown text encoding"):
        ingest_path(
            RecordingStorage(),
            path,
            "source",
            "alpha",
            encoding="NOT_AN_ENCODING",
        )

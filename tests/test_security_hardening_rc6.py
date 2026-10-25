"""0.1.8rc6 hardening: DOCX intake refuses XML declarations and entities; the HTTP body
phase is bounded in total, not per read. No socket is opened: the channel uses fakes."""

import io
import time
import zipfile

import pytest

from factory.health_ui.intake import IntakeRefused, _docx_fragments
from factory.public_fetch.drivers.stdlib import TransportInterrupted, _SocketChannel

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
BODY = '<w:document xmlns:w="' + W + '"><w:body><w:p><w:r><w:t>ordinary text</w:t></w:r></w:p></w:body></w:document>'
RELS = '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'


def docx(document: bytes, rels: bytes | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", document)
        if rels is not None:
            archive.writestr("word/_rels/document.xml.rels", rels)
    return buffer.getvalue()


def test_ordinary_docx_is_still_read():
    assert _docx_fragments(docx(BODY.encode()))


@pytest.mark.parametrize("document, rels", [
    (("<!DOCTYPE w:document>" + BODY).encode(), None),
    (('<!DOCTYPE w:document [<!ENTITY e "safe">]>' + BODY.replace("ordinary text", "&e;")).encode(), None),
    (('<!DOCTYPE w:document [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>'
      + BODY.replace("ordinary text", "&b;")).encode(), None),
    (('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE w:document>' + BODY).encode("utf-16"), None),
    (BODY.encode(), ("<!DOCTYPE Relationships>" + RELS).encode()),
], ids=["doctype", "entity", "nested-entity-expansion", "doctype-utf16", "relationships-doctype"])
def test_docx_with_xml_declarations_or_entities_is_refused(document, rels):
    with pytest.raises(IntakeRefused):
        _docx_fragments(docx(document, rels))


class _Sock:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)


class _Trickle:
    """A peer that sends one byte at a time, each just inside a per-read timeout."""

    def __init__(self, total: int, delay: float):
        self.left, self.delay = total, delay

    def read1(self, n):
        if self.left <= 0:
            return b""
        time.sleep(self.delay)
        self.left -= 1
        return b"x"


class _Conn:
    def close(self):
        pass


def _channel(pending):
    sock = _Sock()
    channel = _SocketChannel(sock, _Conn())
    channel._pending = pending
    return channel, sock


def test_trickled_body_cannot_outlive_the_phase_allowance():
    channel, sock = _channel(_Trickle(total=40, delay=0.03))
    started = time.monotonic()
    with pytest.raises(TransportInterrupted) as refused:
        channel.read_body(max_bytes=40, read_timeout=0.2)
    assert time.monotonic() - started < 0.2 + 0.1
    assert 0 < refused.value.observed_bytes < 40
    assert all(0 < t <= 0.2 + 1e-6 for t in sock.timeouts)


def test_prompt_body_is_read_whole_within_the_allowance():
    channel, _ = _channel(_Trickle(total=5, delay=0.0))
    assert channel.read_body(max_bytes=5, read_timeout=1.0) == b"xxxxx"


class _BlockingSock:
    """Records timeouts; `shutdown` releases a read that is blocked on the peer."""

    def __init__(self):
        import threading
        self.released = threading.Event()

    def settimeout(self, value):
        pass

    def shutdown(self, how):
        self.released.set()


class _StalledPeer:
    """A peer that stalls mid-message (a slow chunk-size line or header): the read
    blocks until the socket is shut down, then fails as a real socket read would."""

    def __init__(self, sock):
        self.sock = sock

    def read1(self, n):
        if not self.sock.released.wait(5):
            return b"late"
        raise OSError("socket shut down")


def test_stalled_chunked_read_ends_at_the_phase_deadline():
    sock = _BlockingSock()
    channel = _SocketChannel(sock, _Conn())
    channel._pending = _StalledPeer(sock)
    started = time.monotonic()
    with pytest.raises(TransportInterrupted):
        channel.read_body(max_bytes=10, read_timeout=0.2)
    assert time.monotonic() - started < 0.2 + 0.5


def test_stalled_response_head_ends_at_the_phase_deadline():
    sock = _BlockingSock()

    class _HeadConn:
        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            if sock.released.wait(5):
                raise OSError("socket shut down")
            raise AssertionError("head phase was not bounded")

        def close(self):
            pass

    channel = _SocketChannel(sock, _HeadConn())
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        channel.request(host="example.test", path_and_query="/", headers={}, read_timeout=0.2)
    assert time.monotonic() - started < 0.2 + 0.5

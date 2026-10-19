"""Benign response framing regressions; in-memory streams only."""
import asyncio

import pytest

from sentinel.core.models import HttpResponse
from sentinel.waf.parser import ParseError
from sentinel.waf.proxy import WafProxy, _read_backend_response, _split_response


def read(raw, method="GET", eof=False):
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(raw)
        if eof:
            reader.feed_eof()
        return await asyncio.wait_for(_read_backend_response(reader, method), .2)
    return asyncio.run(run())


def test_chunked_response_finishes_without_waiting_for_backend_close():
    raw, status = read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Note\r\n\r\n"
                       b"5;source=fixture\r\nhello\r\n6\r\n world\r\n0\r\nX-Note: ordinary\r\n\r\n")
    assert status == 200 and _split_response(raw)[1] == b"hello world"


@pytest.mark.parametrize("method,status", [("HEAD", 200), ("GET", 204), ("GET", 304)])
def test_bodyless_response_does_not_wait_for_advertised_representation(method, status):
    raw, actual = read(f"HTTP/1.1 {status} OK\r\nContent-Length: 123\r\n\r\n".encode(), method)
    assert actual == status and _split_response(raw)[1] == b""


def test_informational_response_precedes_normal_content_length():
    raw, status = read(b"HTTP/1.1 103 Early Hints\r\n\r\n"
                       b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")
    assert status == 200 and _split_response(raw)[1] == b"hello"


def test_close_delimited_response_keeps_body():
    raw, status = read(b"HTTP/1.0 200 OK\r\n\r\nhello", eof=True)
    assert status == 200 and _split_response(raw)[1] == b"hello"


@pytest.mark.parametrize("body", [b"4\r\nhi", b"missing-size\r\n", b"2\r\nhi!!", b"0\r\n"])
def test_incomplete_or_invalid_chunked_response_is_not_returned_as_success(body):
    with pytest.raises((ParseError, asyncio.IncompleteReadError)):
        read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body, eof=True)


class Writer:
    def write(self, data):
        self.data = data

    async def drain(self):
        pass


@pytest.mark.parametrize("status,head_only,expected_length", [(200, False, b"5"), (200, True, b"123"),
                                                            (204, False, None), (304, False, b"123")])
def test_response_emits_one_correct_length_and_no_obsolete_framing(status, head_only, expected_length):
    response = HttpResponse(status=status, body=b"hello", headers={"content-length": "123",
                            "transfer-encoding": "chunked", "Trailer": "X-Note"})
    writer = Writer()
    asyncio.run(WafProxy._send_response(None, writer, response, head_only=head_only))
    head, _, body = writer.data.partition(b"\r\n\r\n")
    lengths = [line.split(b":", 1)[1].strip() for line in head.lower().split(b"\r\n")
               if line.startswith(b"content-length:")]
    assert lengths == ([expected_length] if expected_length else [])
    assert b"transfer-encoding" not in head.lower() and b"trailer:" not in head.lower()
    assert body == (b"" if head_only or status in (204, 304) else b"hello")


def test_repeated_cookies_and_policy_order_survive_response_pipeline():
    items, body = _split_response(
        b"HTTP/1.1 200 OK\r\nSet-Cookie: first=ordinary; Path=/\r\n"
        b"Set-Cookie: second=another; Path=/\r\nReferrer-Policy: unsafe-url\r\n"
        b"Referrer-Policy: same-origin\r\nConnection: keep-alive, X-Fixture-Hop\r\n"
        b"connection: X-Other-Hop\r\nX-Fixture-Hop: local\r\nX-Other-Hop: local\r\n\r\nhello")
    response = HttpResponse(headers=dict(items), header_items=items, body=body)
    writer = Writer()
    asyncio.run(WafProxy._send_response(None, writer, response))
    forwarded, actual_body = _split_response(writer.data)
    assert [v for k, v in forwarded if k.lower() == "set-cookie"] == [
        "first=ordinary; Path=/", "second=another; Path=/"]
    assert [v for k, v in forwarded if k.lower() == "referrer-policy"] == ["unsafe-url", "same-origin"]
    assert not any(k.lower() in {"x-fixture-hop", "x-other-hop"} for k, _ in forwarded)
    assert actual_body == body

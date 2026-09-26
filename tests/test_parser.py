"""协议解析模块单元测试."""
from __future__ import annotations

import pytest

from sentinel.waf.parser import (ParseError, collect_arguments, collect_cookies,
                                 iter_variable_values, parse_request)
from tests.conftest import raw_request


def test_basic_request_line_and_headers():
    req = parse_request(raw_request("GET", "/a/b?x=1&y=2",
                                    {"Host": "h.example", "X-Test": "v"}),
                        "10.0.0.1", 5555)
    assert req.method == "GET"
    assert req.path == "/a/b"
    assert req.query == "x=1&y=2"
    assert req.version == "HTTP/1.1"
    assert req.host == "h.example"
    assert req.get_header("x-test") == "v"
    assert req.remote_addr == "10.0.0.1" and req.remote_port == 5555
    assert req.url == "http://h.example/a/b?x=1&y=2"


def test_lowercase_method_normalised():
    req = parse_request(b"get / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert req.method == "GET"


def test_unsupported_method_rejected():
    with pytest.raises(ParseError):
        parse_request(b"BREW /coffee HTTP/1.1\r\nHost: x\r\n\r\n")


@pytest.mark.parametrize("raw", [
    b"", b"\r\n\r\n", b"GET\r\n\r\n", b"GET / HTTP/9.9\r\nHost: x\r\n\r\n",
    b"GET / HTTP/1.1\r\nBadHeader\r\n\r\n",
    b"GET / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
])
def test_malformed_requests_raise(raw):
    with pytest.raises(ParseError):
        parse_request(raw)


def test_body_content_length_and_truncation():
    body = b"a" * 100
    req = parse_request(raw_request("POST", "/x", body=body), max_body=10)
    assert req.body == b"a" * 10
    assert req.truncated is True


def test_chunked_body_decoded():
    raw = (b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    req = parse_request(raw)
    assert req.body == b"hello world"


def test_query_arguments_parsed_and_duplicates_keep_first():
    req = parse_request(raw_request("GET", "/s?q=a&q=b&empty="))
    args = collect_arguments(req)
    assert args["q"] == "a"
    assert args["empty"] == ""
    assert "q" in iter_variable_values(req, "ARGS_NAMES")


def test_form_body_arguments():
    body = b"user=alice&pass=p%40ss"
    req = parse_request(raw_request("POST", "/login",
                                    {"Content-Type": "application/x-www-form-urlencoded"},
                                    body))
    args = collect_arguments(req)
    assert args == {"user": "alice", "pass": "p@ss"}


def test_json_body_flattened_including_nested():
    body = b'{"user":{"name":"bob","roles":["admin","dev"]},"n":3}'
    req = parse_request(raw_request("POST", "/api",
                                    {"Content-Type": "application/json"}, body))
    args = collect_arguments(req)
    assert args["user.name"] == "bob"
    assert args["user.roles[0]"] == "admin"
    assert args["n"] == "3"


def test_json_body_sniffed_without_content_type():
    body = b'{"query":"1 OR 1=1"}'
    req = parse_request(raw_request("POST", "/api", body=body))
    assert collect_arguments(req)["query"] == "1 OR 1=1"


def test_multipart_body_arguments():
    body = (b"--BOUND\r\nContent-Disposition: form-data; name=\"file\"; "
            b"filename=\"a.txt\"\r\n\r\nhello\r\n--BOUND--\r\n")
    req = parse_request(raw_request("POST", "/upload",
                                    {"Content-Type": "multipart/form-data; boundary=BOUND"},
                                    body))
    assert collect_arguments(req)["file"] == "hello"


def test_variable_selectors():
    req = parse_request(raw_request("POST", "/p?q=1",
                                    {"User-Agent": "UA/1", "Cookie": "sid=abc; theme=dark",
                                     "Referer": "http://r/"},
                                    b"a=b"), "1.2.3.4", 1)
    assert iter_variable_values(req, "REQUEST_URI") == ["/p?q=1"]
    assert iter_variable_values(req, "REQUEST_METHOD") == ["POST"]
    assert iter_variable_values(req, "REQUEST_HEADERS:user-agent") == ["UA/1"]
    assert iter_variable_values(req, "REMOTE_ADDR") == ["1.2.3.4"]
    assert iter_variable_values(req, "REQUEST_COOKIES:sid") == ["abc"]
    assert set(iter_variable_values(req, "REQUEST_COOKIES")) == {"sid=abc", "theme=dark"}
    assert iter_variable_values(req, "ARGS:a") == ["b"]
    assert iter_variable_values(req, "ARGS:missing") == []
    assert iter_variable_values(req, "UNKNOWN_VAR") == []


def test_cookies_helper():
    req = parse_request(raw_request("GET", "/", {"Cookie": "a=1; b=2"}))
    assert collect_cookies(req) == {"a": "1", "b": "2"}


def test_header_continuation_and_duplicate_merge():
    raw = (b"GET / HTTP/1.1\r\nHost: x\r\nX-Multi: a\r\nX-Multi: b\r\n"
           b"Accept: */*\r\n\r\n")
    req = parse_request(raw)
    assert req.get_header("X-Multi") == "a, b"


def test_large_header_block_rejected():
    big = b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: " + b"a" * 70000 + b"\r\n\r\n"
    with pytest.raises(ParseError):
        parse_request(big)

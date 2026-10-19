"""Ordinary upload limits must be enforced before reading or forwarding the body."""
import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sentinel.core.config import Config
from sentinel.waf.proxy import WafProxy


class Writer:
    data = b""

    def write(self, data):
        self.data += data

    async def drain(self):
        pass


def header(size):
    return f"POST /form HTTP/1.1\r\nHost: fixture.local\r\nContent-Length: {size}\r\n\r\n".encode()


@pytest.mark.parametrize("mode", ["block", "detect", "off"])
@pytest.mark.parametrize("inspect_body", [True, False])
@pytest.mark.parametrize("limit", [0, 16])
def test_oversize_is_rejected_before_body_read_and_inspection(mode, inspect_body, limit):
    async def run():
        config = Config()
        config.waf.max_body_bytes = limit
        config.waf.mode = mode
        config.waf.inspect_body = inspect_body
        engine = SimpleNamespace(inspect=Mock(side_effect=AssertionError("must not inspect")))
        proxy = WafProxy(config, engine=engine)
        reader = asyncio.StreamReader()
        reader.feed_data(header(limit + 1))  # No body or EOF: a read would wait indefinitely.
        writer = Writer()
        await asyncio.wait_for(proxy._serve_connection(reader, writer, ("127.0.0.1", 1234)), .2)
        assert writer.data.startswith(b"HTTP/1.1 413 Content Too Large\r\n")
        assert b"Connection: close\r\n" in writer.data
        engine.inspect.assert_not_called()
    asyncio.run(run())


@pytest.mark.parametrize("limit,size", [(0, 0), (1, 0), (1, 1), (16, 15), (16, 16)])
def test_allowed_upload_is_preserved_byte_for_byte(limit, size):
    async def run():
        config = Config()
        config.waf.max_body_bytes = limit
        proxy = WafProxy(config, engine=SimpleNamespace())
        raw = header(size) + b"a" * size
        reader = asyncio.StreamReader()
        reader.feed_data(raw)
        assert await asyncio.wait_for(proxy._read_request(reader), .2) == raw
    asyncio.run(run())


def test_hot_lowered_limit_rejects_already_truncated_parser_result():
    async def run():
        config = Config()
        proxy = WafProxy(config, engine=SimpleNamespace(inspect=Mock(side_effect=AssertionError("must not inspect"))))

        class Reader(asyncio.StreamReader):
            async def readexactly(self, size):
                config.waf.max_body_bytes = 0
                return await super().readexactly(size)

        reader = Reader()
        reader.feed_data(header(1) + b"a")
        writer = Writer()
        await asyncio.wait_for(proxy._serve_connection(reader, writer, ("127.0.0.1", 1234)), .2)
        assert writer.data.startswith(b"HTTP/1.1 413 ")
        proxy.engine.inspect.assert_not_called()
    asyncio.run(run())

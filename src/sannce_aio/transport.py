import asyncio

import aiohttp

from .errors import ConnectError

_CLOSED = (
    aiohttp.WSMsgType.CLOSE,
    aiohttp.WSMsgType.CLOSING,
    aiohttp.WSMsgType.CLOSED,
    aiohttp.WSMsgType.ERROR,
)


class WsTransport:
    def __init__(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        self._ws = ws

    @classmethod
    async def open(
        cls, session: aiohttp.ClientSession, url: str, timeout: float
    ) -> "WsTransport":
        try:
            async with asyncio.timeout(timeout):
                ws = await session.ws_connect(url, autoping=True, max_msg_size=0)
        except (aiohttp.ClientError, OSError, TimeoutError) as exc:
            raise ConnectError(f"cannot reach {url}: {exc}") from exc
        return cls(ws)

    async def read(self) -> bytes:
        while True:
            try:
                message = await self._ws.receive()
            except (aiohttp.ClientError, OSError):
                return b""
            if message.type is aiohttp.WSMsgType.BINARY:
                return bytes(message.data)
            if message.type in _CLOSED:
                return b""

    async def write(self, data: bytes) -> None:
        try:
            await self._ws.send_bytes(data)
        except (aiohttp.ClientError, ConnectionError, RuntimeError) as exc:
            raise ConnectError(f"send failed: {exc}") from exc

    async def close(self) -> None:
        await self._ws.close()

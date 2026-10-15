import asyncio
import hashlib
import re
import struct

REALM = "RTSP"
NONCE = "a1b2c3d4"


def md5(text):
    return hashlib.md5(text.encode()).hexdigest()


class FakeRtspCamera:
    def __init__(
        self,
        *,
        username="admin",
        password="admin123",
        backchannel=True,
        payload_types=(0, 8),
        setup_status=200,
        qop=False,
        auth=True,
        stall_after_play=False,
    ):
        self.username = username
        self.password = password
        self.backchannel = backchannel
        self.payload_types = payload_types
        self.setup_status = setup_status
        self.qop = qop
        self.auth = auth
        self.stall_after_play = stall_after_play
        self.host = "127.0.0.1"
        self.port = 0
        self.requests = []
        self.packets = []
        self.arrivals = []
        self.nonce = NONCE
        self.stale_replies = 0
        self._server = None
        self._writers = set()
        self._connections = 0
        self._logins = 0

    async def start(self):
        self._server = await asyncio.start_server(self._handle, self.host, 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self):
        self._server.close()
        for writer in list(self._writers):
            writer.close()
        await self._server.wait_closed()

    def sdp(self, url):
        lines = [
            "v=0", "o=- 1 1 IN IP4 127.0.0.1", "s=fake", "t=0 0",
            f"a=control:{url}/",
            "m=video 0 RTP/AVP 96", "a=recvonly", f"a=control:{url}/trackID=1",
            "a=rtpmap:96 H265/90000",
            "m=audio 0 RTP/AVP 8", "a=recvonly", f"a=control:{url}/trackID=2",
            "a=rtpmap:8 PCMA/8000/1",
        ]
        if self.backchannel:
            types = " ".join(str(pt) for pt in self.payload_types)
            lines += [f"m=audio 0 RTP/AVP {types}", "a=sendonly", "a=control:trackID=3"]
        return "\r\n".join(lines) + "\r\n"

    def _authorized(self, method, header):
        if not header.startswith("Digest "):
            return False
        parts = dict(re.findall(r'(\w+)="?([^",]*)"?', header))
        ha1 = md5(f"{self.username}:{REALM}:{self.password}")
        ha2 = md5(f"{method}:{parts.get('uri', '')}")
        if self.qop:
            expected = md5(f"{ha1}:{self.nonce}:{parts.get('nc')}:{parts.get('cnonce')}:auth:{ha2}")
        else:
            expected = md5(f"{ha1}:{self.nonce}:{ha2}")
        return parts.get("response") == expected

    async def _handle(self, reader, writer):
        self._writers.add(writer)
        self.nonce = f"{NONCE}{self._connections}"
        self._connections += 1
        try:
            while True:
                first = await reader.readexactly(1)
                if first == b"$":
                    channel, length = struct.unpack("!BH", await reader.readexactly(3))
                    packet = await reader.readexactly(length)
                    self.packets.append((channel, packet))
                    self.arrivals.append(asyncio.get_running_loop().time())
                    continue
                head = (first + await reader.readuntil(b"\r\n\r\n")).decode()
                start, *lines = head.strip().split("\r\n")
                method, url, _ = start.split(" ")
                headers = {
                    name.lower(): value
                    for name, value in (line.split(": ", 1) for line in lines)
                }
                self.requests.append((method, url, headers))
                writer.write(self._reply(method, url, headers).encode())
                await writer.drain()
                if method == "PLAY" and self.stall_after_play:
                    writer.transport.pause_reading()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self._writers.discard(writer)
            writer.close()

    def _challenge(self, cseq, extra):
        qop = ', qop="auth"' if self.qop else ""
        return (
            f"RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\n"
            f'WWW-Authenticate: Digest realm="{REALM}", nonce="{self.nonce}"{qop}{extra}\r\n\r\n'
        )

    def _reply(self, method, url, headers):
        cseq = headers.get("cseq", "0")
        header = headers.get("authorization", "")
        if header and self._logins and self.stale_replies:
            self.stale_replies -= 1
            self.nonce += "x"
            return self._challenge(cseq, ", stale=true")
        if self.auth and not self._authorized(method, header):
            return self._challenge(cseq, "")
        self._logins += 1
        if method == "DESCRIBE":
            body = self.sdp(url)
            return (
                f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Type: application/sdp\r\n"
                f"Content-Base: {url}/\r\nContent-Length: {len(body)}\r\n\r\n{body}"
            )
        if method == "SETUP":
            if self.setup_status != 200:
                return f"RTSP/1.0 {self.setup_status} Refused\r\nCSeq: {cseq}\r\n\r\n"
            return (
                f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nSession: 1234;timeout=60\r\n"
                f"Transport: {headers.get('transport', '')}\r\n\r\n"
            )
        return f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nSession: 1234\r\n\r\n"


class RawClient:
    def __init__(self, reader, writer, nonce, base):
        self.reader = reader
        self.writer = writer
        self.nonce = nonce
        self.base = base
        self.cseq = 0
        self.body = ""

    @classmethod
    async def connect(cls, port, base=None):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 0\r\n\r\n")
        head = (await reader.readuntil(b"\r\n\r\n")).decode()
        nonce = re.search(r'nonce="([^"]+)"', head).group(1)
        return cls(reader, writer, nonce, base or f"rtsp://127.0.0.1:{port}/1/1")

    async def request(self, method, path="", extra=""):
        url = self.base + path
        self.cseq += 1
        response = md5(f"{md5('admin:RTSP:admin123')}:{self.nonce}:{md5(f'{method}:{url}')}")
        auth = (
            f'Authorization: Digest username="admin", realm="RTSP", nonce="{self.nonce}", '
            f'uri="{url}", response="{response}"\r\n'
        )
        self.writer.write(
            f"{method} {url} RTSP/1.0\r\nCSeq: {self.cseq}\r\n{extra}{auth}\r\n".encode()
        )
        head = (await self.reader.readuntil(b"\r\n\r\n")).decode()
        length = re.search(r"Content-Length: (\d+)", head)
        body = await self.reader.readexactly(int(length.group(1))) if length else b""
        self.body = body.decode()
        return head

    async def play_video(self):
        await self.request("DESCRIBE")
        await self.request("SETUP", "/trackID=1", "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n")
        return await self.request("PLAY")

    async def until_closed(self):
        return await asyncio.wait_for(self.reader.read(), 2)

    def close(self):
        self.writer.close()

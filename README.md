# sannce-aio

Asyncio library for SANNCE / Tiandy wired IP cameras on the LAN. The reference model is the I91FW.

The library is local only and needs no cloud. It uses two ports on the camera: TCP 3000 for the private protocol and HTTP 80 for settings. For RTSP on port 554 it only builds URLs. The camera must be activated and on the LAN, with its admin password set.

Not included: video decoding, ONVIF and multi-channel devices. The library drives one channel: HTTP channel 1, private-protocol channel 0, RTSP `/1/n`.

## Status

Not verified on hardware. The protocol was reverse-engineered statically from the vendor app and SDK. No part of it has run against a real camera. The tests use a simulator built from the same spec. They show that the code matches the spec, not that the camera does.

Behavior may change after the first run on a real I91FW. Likely trouble spots:

- HTTP settings. The vendor app sends these requests through its cloud, not to the camera. Whether the camera's own web server answers them, and which login it takes, is open. `connect()` asks for HTTP capabilities first, so it fails on a camera that does not answer.
- Login. The library sends only the first phase of the app's login: credentials in base64. Whether the camera finishes the login after that phase is open. Failure replies are not decoded.
- Talk. The camera's accept, refuse and end replies are inferred from SDK code, not seen from a camera.
- Events. Stop codes and `VCA` rule values are partly inferred. Only two rule values are mapped.
- Discovery. The ports the camera answers on, and its reply layout, are open.

The spec and its open questions are in [docs/protocol.md](../docs/protocol.md). The checks to run when a camera is on the bench are in [docs/hardware-checklist.md](../docs/hardware-checklist.md).

## Install

Python 3.11 or newer. The only runtime dependency is aiohttp 3.12 or newer. The tests have run on Python 3.14 only.

Run from the repository root. The second command is an editable install that adds pytest.

```sh
pip install ./lib
pip install -e "./lib[dev]"
```

## Quick start

```python
import asyncio

from sannce_aio import SannceCamera


async def main() -> None:
    camera = SannceCamera("192.168.1.10", "admin", "PASSWORD")
    camera.subscribe(print)
    await camera.connect()
    try:
        print(camera.info, sorted(camera.caps))
        await asyncio.sleep(60)
    finally:
        await camera.close()


asyncio.run(main())
```

Subscribe before `connect()`: events can arrive as soon as the login ends. Always call `close()`.

## SannceCamera

```python
SannceCamera(host, username, password, *, nvs_port=3000, http_port=80,
             rtsp_port=554, session=None, event_timeout=10.0)
```

The same user and password go to the private protocol and to HTTP. `host` must not be empty or contain `/ ? # @` (else `ValueError`). `session` is an optional `aiohttp.ClientSession` for the HTTP calls. The library never closes a session you pass.

| Member | What it does |
|---|---|
| `await connect()` | Asks HTTP for capabilities, logs in on the private port, then reads `info` and `caps`. Raises `AuthError`, `ConnectError` or `ProtocolError`. |
| `await close()` | Stops reconnecting, cancels event timers and closes the connections. |
| `info` | `CameraInfo(model, serial, firmware, mac)`. Expect only `firmware`. See Info and discovery. |
| `caps` | `frozenset[str]`. `person`, `vehicle` and `motion` come from the camera's capability reply. `white_light` and `light_mode` appear when the read works. `talk` is always there: it says the library can talk, not that the camera was asked. |
| `rtsp_url(stream="main")` | `rtsp://user:pass@host:554/1/1`. `"sub"` gives `/1/2`. User and password are percent-encoded. Other values raise `ValueError`. |
| `subscribe(callback)` | Calls `callback(Event)` for each event. Returns a function that removes the callback. |
| `on_availability(callback)` | Calls `callback(bool)` when the private connection comes up or goes down. |
| `on_login_failed(callback)` | Calls `callback(AuthError)` when the library stops reconnecting because the camera refused the login. |
| `await get_light()` | `True` only when the light is forced on. `False` in auto mode, even if the lamp is lit. |
| `await set_light(on)` | `True` forces the light on. `False` returns it to auto, not to forced off. |
| `await get_light_mode()` | `"infrared"`, `"smart"`, `"color"` or `"custom"`. |
| `await set_light_mode(mode)` | `"infrared"`, `"smart"` or `"color"`. Anything else raises `ValueError`. `"custom"` is read-only. |
| `await get_detection()` | `Detection(person, vehicle, motion)`, three bools. |
| `await set_detection(*, person=None, vehicle=None, motion=None)` | Changes only the flags you pass. |
| `await play_audio(pcm)` | Sends audio to the camera speaker. See Audio. |

### Events

```python
from sannce_aio import Event


def on_event(event: Event) -> None:
    print(event.kind, event.active, event.channel)


unsubscribe = camera.subscribe(on_event)
```

`Event(kind, active, channel)`. `active` is `True` at the start and `False` at the stop. `channel` is 0-based, as on the wire.

| kind | camera message |
|---|---|
| `motion` | `MOTIONDETECT`, or `NOTIFY` sub-type 2 |
| `vehicle` | `MOTIONDETECT_CAR` |
| `intrusion` | `VCA` rule 2 |
| `line` | `VCA` rule 0 |
| `tamper` | `VIDEOCOVER`, or `NOTIFY` sub-type 3 |
| `video_loss` | `VIDEOLOST`, or `NOTIFY` sub-type 0 |

- There is no person event. The private protocol has none, and a person can only show up as plain `motion` (inferred). Person detection is a setting: use `get_detection()` and `set_detection(person=True)`. A separate person source may exist in ONVIF (see check 6.3 in the hardware checklist). The library does not read ONVIF.
- Other alarm kinds and other `VCA` rules are dropped.
- The camera may never send a stop. If none arrives within `event_timeout` seconds of the last start, the library emits the stop itself.
- Callbacks run on the event loop. A callback that raises is logged, and the others still run.

### Availability

`on_availability` fires with `True` after the login and after each reconnect, and with `False` when the connection drops or `close()` runs. Register it before `connect()` to get the first `True`. A callback cannot be removed.

After a drop the library retries at once, then waits 1 s, doubling the wait up to 60 s. It gives up after 3 refused logins, logs an error and calls each `on_login_failed` callback with the last `AuthError`. The connection then stays down. The retries and the return are logged at debug level on the `sannce_aio.connection` logger, the give-up as an error.

The library sends a heartbeat every 3 s but has no silence timeout yet. A camera that stops without closing the TCP connection can stay "available" until the operating system gives up on it. See "Silence timeout" in docs/protocol.md.

### Info and discovery

After `connect()`, `info.firmware` holds the firmware version read over HTTP. `model`, `serial` and `mac` are best-effort. The library fills them only if the camera's device info carries them. The vendor app's own bean has none of the three. Expect `None`. Read them from `discover()`, which takes them from the camera's search reply.

```python
import asyncio

from sannce_aio import discover


async def main() -> None:
    for found in await discover(timeout=3.0):
        print(found.ip, found.serial, found.model, found.mac)


asyncio.run(main())
```

`discover()` returns `list[DiscoveredCamera]` with `ip`, `mac`, `serial`, `model`, `http_port`, `server_port` and `channels`. It sends a UDP multicast search and collects replies for `timeout` seconds. Run it on the camera's LAN.

### Audio

`play_audio(pcm)` takes an async iterable of `bytes`: 16-bit signed little-endian mono PCM at 8000 Hz, in chunks of any size. The library encodes G.711 A-law and sends 10 ms frames at real-time speed. It ends the talk session when the stream ends, fails or is cancelled. It raises `TalkBusyError` if the camera refuses talk. Two calls on one `SannceCamera` run one after the other: the second waits for the first.

`play_audio` sends audio to the camera and does not receive any. The camera-side replies are inferred (see Status).

### Errors

| Exception | Raised when |
|---|---|
| `SannceError` | Base class of the four below. |
| `ConnectError` | The camera is unreachable, a request times out, or the connection is closed or dropped. |
| `AuthError` | HTTP answers 401 or 403, the camera refuses a login, or the private login does not finish in 10 s. A user name or password over 16 bytes (UTF-8) also raises it. |
| `ProtocolError` | A reply cannot be parsed, or the camera refuses a write. |
| `TalkBusyError` | The camera refuses talk. |

Bad arguments raise `ValueError`.

## Login

Traffic is not encrypted. The private login sends base64, which hides nothing. The Digest fallback puts the password in the query string, as the app does. Use a trusted LAN.

### HTTP

The settings API tries the SHA-256 session login first. It falls back to HTTP Digest when `SessionCheck` fails. A refused session login raises `AuthError` and does not fall back. After a session login, a request that gets 401 or 403 triggers one new login and one retry.

### Private protocol

The default step is `PlaintextLogin`. It sends one `USER LOGON` message with the user name and password in base64. Each is 16 bytes of UTF-8 at most. `SannceCamera` always uses it.

A login step is any object with two methods (the `LoginStep` protocol in `sannce_aio.login`):

```python
from sannce_aio.login import LoginResult


class MyLogin:
    def build_logon(self, username: str, password: str, seq: int) -> bytes: ...

    def interpret_reply(self, fields: list[str]) -> LoginResult: ...
```

- `build_logon` returns one complete frame. Build it with `sannce_aio.protocol.build_command`. `PlaintextLogin(device_ip)` puts the camera address in the first field, and a custom step must do the same. The connection calls `build_logon` on every connect and reconnect.
- `interpret_reply` gets the fields of each camera message, device address and route first. It returns `LoginResult(success=True)` for the message that ends the login. `success=False` means "not finished", not "refused". After 10 s without success the connection raises `AuthError`.

Pass the step to the connection:

```python
import asyncio

from sannce_aio.connection import NvsConnection


async def main() -> None:
    connection = NvsConnection(
        "192.168.1.10", 3000, MyLogin(), on_event=print, on_availability=print
    )
    await connection.connect("admin", "PASSWORD")
    try:
        await asyncio.sleep(60)
    finally:
        await connection.close()


asyncio.run(main())
```

`SannceCamera` has no `login` argument yet. It builds its own connection with `PlaintextLogin`.

The encrypted login is documented, not implemented. Some cameras may refuse the plaintext login and ask for a digest login. Its spec lives in a separate branch or module, not in docs/protocol.md here. That login needs a second logon message after the camera's first reply, and a step cannot send one yet. On a camera that insists on it, the private login ends in `AuthError`: a timeout or a closed connection. Check 4.1 of the hardware checklist finds out which login the I91FW accepts.

## CLI

```sh
python -m sannce_aio discover [--timeout SECONDS] [--json]
python -m sannce_aio probe HOST [--user USER] [--pass PASSWORD] [--nvs-port PORT]
                                [--http-port PORT] [--duration SECONDS]
                                [--no-light] [--json]
```

`discover` prints one line per camera, or `no cameras found`. The values here are made up:

```
ip=192.168.1.10 mac=00:00:5E:00:53:2A serial=SN0000000001 model=MODEL-X http_port=80 server_port=3000 channels=1
```

`probe` connects, prints `info` and `caps`, switches the white light on and back, then prints events until Ctrl-C or `--duration`. Sample output, from the simulator:

```
info: model=unknown serial=unknown firmware=1.0.0 mac=unknown
caps: light_mode motion person talk vehicle white_light
light: off -> on -> off
watching events
event: motion active channel=0
event: motion clear channel=0
```

- The light test ends with the light forced on if it was on before, and in auto mode otherwise. `--no-light` skips it.
- `--json` prints one JSON object per line, and nothing when `discover` finds no camera. `probe` objects carry a `type`: `info`, `caps`, `light`, `watching` or `event`. `discover` objects hold the camera fields.
- Defaults: user `admin`, empty password, ports 3000 and 80.
- Exit code 0 on success, 1 on an error (message on stderr), 2 on bad arguments (usage on stderr), 130 on Ctrl-C.

## Simulator

`python -m sannce_aio simulate` runs `sannce_aio.simulator.CameraSimulator` as a fake camera. The bench in `bench/` runs it in a container. It follows the same spec as the library, so it shows that the parts fit together, not that a camera behaves this way.

```sh
python -m sannce_aio simulate [--host HOST] [--nvs-port PORT] [--http-port PORT]
                              [--control-port PORT] [--user USER] [--pass PASSWORD]
                              [--model MODEL] [--serial SERIAL] [--mac MAC]
```

- Defaults: host `0.0.0.0`, private protocol port 3000, HTTP port 80, control port 8099, user `admin`, password `admin123`, model `I91FW-SIM`, serial `SIM0000000001`, MAC `00:00:5E:00:53:01`.
- It answers the LAN search on UDP 3000 and 4000, on every address. It joins both search groups on the interface that `--host` names, or on any interface for `0.0.0.0`. `--model`, `--serial` and `--mac` go into that reply.
- Port 80 needs root outside a container. Docker lets any user bind it inside one.
- It prints one line when it is ready, then runs until Ctrl-C.

The control API takes and returns JSON over HTTP, with no login. Keep it off untrusted networks.

| Request | Effect |
|---|---|
| `GET /state` | light, light mode, detection flags, client count, talking, user and password |
| `POST /event {"kind", "active"}` | push an event. `kind` is `motion`, `vehicle`, `intrusion`, `line`, `tamper` or `video_loss`. `active` is true or false |
| `POST /settings {"light", "light_mode", "detection"}` | change any of them, as the vendor app would. `light` is true or false, and false means auto. `light_mode` is `infrared`, `smart` or `color`. `detection` is an object of `person`, `vehicle` and `motion` booleans, each optional |
| `POST /password {"password"}` | change the password that new logins must use. Open sessions stay |
| `POST /drop {"seconds"}` | refuse connections on the private protocol port only, for `seconds` (0 to 3600), like a reboot. Its open sessions close and HTTP sessions end, but the HTTP port keeps answering. The LAN search gets no answer |
| `POST /talk-busy {"busy"}` | refuse talk requests while `busy` is true, as if the app held the channel |
| `GET /audio.wav` | the current or last talk session as 8 kHz mono 16-bit WAV |
| `POST /reset` | back to the start state |

Requests that change something answer 204. A bad body answers 400 with a one-line reason.

## Tests

```sh
pip install -e "./lib[dev]"
python -m pytest lib/tests -q
```

The tests run against `sannce_aio.simulator.CameraSimulator`, a fake camera on localhost. They need no camera.

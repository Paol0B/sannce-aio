# sannce-aio

Asyncio library for SANNCE / Tiandy wired IP cameras on the LAN. The reference model is the I91FW. The camera reports it as I91FX.

The library is local only and needs no cloud. It uses three ports on the camera:

- 3002 for the private protocol, which runs inside a WebSocket. Events arrive here.
- 80 (HTTP) for settings.
- 554 (RTSP) for the video URLs, and for sending audio to the speaker through the ONVIF backchannel.

The camera must be activated and on the LAN, with its admin password set.

Not included: video decoding, ONVIF and multi-channel devices. The library drives one channel: HTTP channel 1, private-protocol channel 0, RTSP `/1/n`.

## Status

Measured on the I91FX by hand (SANNCE I91FX, sold as I91FW, firmware `NVSS_V29.0.23.20250330`, 2026-10-15): the salted WebSocket login, motion and person events, the floodlight, the built-in warning sounds, and audio through the RTSP backchannel.

The acceptance run with Home Assistant on that camera is done. Still pending on that camera:

- The vehicle event (`MOTIONDETECT_CAR`) and the tamper event (`VIDEOCOVER`).
- The stop action of a built-in sound, and the length of each sound.
- Whether motion plays the sound linked on the VMD trigger.

Other models and firmware may differ. Port 3000, the app SDK's TCP port, is closed on the I91FX. The library has no TCP transport.

The spec and its open questions are in [docs/protocol.md](https://github.com/Paol0B/ha-sannce/blob/master/docs/protocol.md). The checks to run when a camera is on the bench are in [docs/hardware-checklist.md](https://github.com/Paol0B/ha-sannce/blob/master/docs/hardware-checklist.md).

## Install

Python 3.11 or newer. The only runtime dependency is aiohttp 3.12 or newer. CI runs the tests on Python 3.11 to 3.14.

The library is not on PyPI yet. Run from the directory that holds `pyproject.toml`. The second command is an editable install that adds pytest.

```sh
pip install .
pip install -e ".[dev]"
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
SannceCamera(host, username, password, *, nvs_port=3002, http_port=80,
             rtsp_port=554, session=None, event_timeout=10.0)
```

The same user and password go to the private protocol, to HTTP and to RTSP. `nvs_port` is the camera's WebSocket port. `host` must not be empty or contain `/ ? # @` (else `ValueError`). `session` is an optional `aiohttp.ClientSession` for the HTTP calls and the WebSocket. The library never closes a session you pass.

| Member | What it does |
|---|---|
| `await connect()` | Asks HTTP for capabilities, logs in over the WebSocket, asks RTSP for a backchannel, then reads `info` and `caps`. Raises `AuthError`, `ConnectError` or `ProtocolError`. |
| `await close()` | Stops reconnecting, cancels event timers and closes the connections. |
| `info` | `CameraInfo(model, serial, firmware, mac)`. Expect only `firmware`. See Info and discovery. |
| `caps` | `frozenset[str]`. `person`, `vehicle` and `motion` come from the camera's capability reply. `white_light`, `light_mode`, `volume` and `siren_on_event` appear when the read works. `siren` appears when the camera lists built-in warning sounds. `speaker` appears when the RTSP stream `/1/1` offers an audio backchannel. A cap is left out only when the camera refuses the read or answers it badly; when HTTP or RTSP cannot be reached, `connect()` raises `ConnectError` instead. |
| `rtsp_url(stream="main")` | `rtsp://user:pass@host:554/1/1`. `"sub"` gives `/1/2`. User and password are percent-encoded. Other values raise `ValueError`. |
| `subscribe(callback)` | Calls `callback(Event)` for each event. Returns a function that removes the callback. |
| `on_availability(callback)` | Calls `callback(bool)` when the private connection comes up or goes down. |
| `on_login_failed(callback)` | Calls `callback(AuthError)` when the library stops reconnecting because the camera refused the login. |
| `await get_floodlight()` | `Floodlight(on, brightness)`. `on` is true only when the lamp is forced on in color or custom mode, false otherwise even if the lamp is lit. `brightness` is the lamp power, 1 to 100. |
| `await set_floodlight(on, *, brightness=None, base_mode="smart")` | `True` switches to color mode when the mode is not color or custom, then lights the lamp for the whole day at `brightness` (the current power by default). It does so with a timed window from 00:00 to 23:59, so the lamp goes dark for one minute at 23:59, and the camera's own timed window is lost. `False` returns to `base_mode`: `"infrared"`, `"smart"` or `"color"`. |
| `await get_light_mode()` | `"infrared"`, `"smart"`, `"color"` or `"custom"`. |
| `await set_light_mode(mode)` | `"infrared"`, `"smart"` or `"color"`. Anything else raises `ValueError`. `"custom"` is read-only. |
| `await get_detection()` | `Detection(person, vehicle, motion, sensitivity)`: three bools and the motion sensitivity, 0 to 100, or `None`. |
| `await set_detection(*, person=None, vehicle=None, motion=None)` | Changes only the flags you pass. |
| `await set_sensitivity(level)` | Motion sensitivity, 0 to 100. |
| `sound_count` | How many built-in warning sounds the camera has. 0 before `connect()`. |
| `await play_sound(sample)` / `await stop_sound(sample)` | Plays or stops a built-in warning sound. `sample` counts from 0. The stop action is not confirmed on the camera. |
| `await get_volume()` / `await set_volume(volume)` | The camera's output volume (`outputVolume`), 0 to 100. It sets the speaker loudness. |
| `await get_siren_on_event()` / `await set_siren_on_event(on)` | Whether motion plays built-in sound 1. |
| `await play_audio(pcm)` | Sends audio to the camera speaker through the RTSP backchannel. See Audio. |

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

- There is no person event. On the I91FX, with person and vehicle detection on and all-motion detection off, `MOTIONDETECT` means a person: an object that moved with no person in view gave no event. The library reports it as `motion`. With all-motion detection on, a person cannot be told from other motion. Person detection is a setting: use `get_detection()` and `set_detection(person=True)`. The library does not read ONVIF.
- The camera sends the start about once a second while an event lasts, and one stop at the end. Every start reaches the callbacks. The library takes alarms with route `IP` or `PROXY`.
- Other alarm kinds and other `VCA` rules are dropped.
- A stop ends the event at once. If no start or stop arrives within `event_timeout` seconds of the last start, the library emits the stop itself.
- Callbacks run on the event loop. A callback that raises is logged, and the others still run.

### Availability

`on_availability` fires with `True` after the login and after each reconnect, and with `False` when the connection drops or `close()` runs. Register it before `connect()` to get the first `True`. A callback cannot be removed.

After a drop the library retries at once, then waits 1 s, doubling the wait up to 60 s. It gives up after 3 refused logins, logs an error and calls each `on_login_failed` callback with the last `AuthError`. The connection then stays down. The retries and the return are logged at debug level on the `sannce_aio.connection` logger, the give-up as an error.

The library sends an empty command frame every 5 s. The camera sends something about every 10 s, even when idle. After 20 s without data the library drops the connection and reconnects. The camera's idle messages (`CMD EXCEPTION` and empty `PROXY`) are not events.

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

`find_camera(ip, timeout=2.0)` looks for one camera. It sends the same search to the groups and to `ip` itself on ports 3000 and 4000, and returns the `DiscoveredCamera` whose `ip` matches as soon as it answers. It returns `None` when nothing answers within `timeout` seconds, or at once when `ip` is not an IPv4 address.

### Audio

`play_audio(pcm)` takes an async iterable of `bytes`: 16-bit signed little-endian mono PCM at 8000 Hz, in chunks of any size. The library sends it to the camera speaker through the ONVIF backchannel on the main stream `/1/1`:

1. `DESCRIBE` with `Require: www.onvif.org/ver20/backchannel`, answering the Digest login. It picks the `sendonly` audio track, PCMA before PCMU.
2. `SETUP` with `RTP/AVP/TCP` interleaved, then `PLAY`.
3. G.711 RTP packets of 20 ms at real-time speed. On a long stream it sends `GET_PARAMETER` every 30 s.
4. `TEARDOWN` when the stream ends, fails or is cancelled.

It raises `TalkBusyError` if the camera refuses the audio channel with a busy status (RTSP 453, 454, 455 or 461). It raises `ProtocolError` if the stream has no backchannel track. Two calls on one `SannceCamera` run one after the other: the second waits for the first.

`play_audio` sends audio to the camera and does not receive any. The camera does not play audio sent over the WebSocket.

### RTSP relay

```python
from sannce_aio import RtspRelay

relay = RtspRelay("192.168.1.10", 554)
await relay.start()
url = f"rtsp://admin:PASSWORD@127.0.0.1:{relay.port}/1/2"
...
await relay.close()
```

`RtspRelay(host, port, *, listen_host="127.0.0.1", timeout=10.0)` listens on a free port of `listen_host`. `port` gives it after `start()`. Each client connection gets its own connection to the camera's RTSP port. Bytes pass both ways unchanged, so the client's URL and Digest login work as they are: the I91FX answers with the host the client put in its request.

The I91FX answers a second `SETUP` of the same track in one session with `455 Method Not Valid in This State`. Home Assistant's go2rtc sends one for every talk session after the first on a stream it reads. The relay answers that `SETUP` itself, with `200 OK`, the client's `CSeq`, and the `Session` and `Transport` of the camera's first answer. It sends this answer after the camera's answers to earlier requests, and never inside an interleaved frame. The relay matches the camera's answers to requests by `CSeq`. An answer with an unknown `CSeq` passes unchanged and counts for no request. A `TEARDOWN` makes the relay forget the tracks of that connection.

- When either side closes or fails, the relay closes both. So does an RTSP message it cannot parse, or one whose head or body is above 64 KiB. A camera that does not accept the connection within `timeout` seconds closes the client. The reasons are logged at debug level on the `sannce_aio.relay` logger.
- `close()` stops listening and ends every connection within about 2 seconds.

### Errors

| Exception | Raised when |
|---|---|
| `SannceError` | Base class of the four below. |
| `ConnectError` | The camera is unreachable, a request times out, the connection is closed or dropped, or the private login does not finish in 10 s. |
| `AuthError` | HTTP answers 401 or 403, RTSP answers 401 after the Digest retry, or the camera refuses the private login. A user name or password over 16 bytes (UTF-8) also raises it. |
| `ProtocolError` | A reply cannot be parsed, or the camera refuses a write. |
| `TalkBusyError` | The camera refuses the audio channel. |

Bad arguments raise `ValueError`.

## Login

Traffic is not encrypted. The WebSocket is plain `ws://`, and the first logon message sends the user name and password in base64, which hides nothing. The Digest fallback puts the password in the query string, as the app does. Use a trusted LAN.

### HTTP

The settings API tries the SHA-256 session login first. It falls back to HTTP Digest when `SessionCheck` fails. A refused session login raises `AuthError` and does not fall back. After a session login, a request that gets 401 or 403 triggers one new login and one retry.

### Private protocol

The connection is a WebSocket to `ws://<host>:<nvs_port>`, with no path and no subprotocol. Each binary message holds one or more frames.

The default step is `SaltedLogin`. `SannceCamera` always uses it.

1. It sends `USER LOGON` with the user name and password in base64. Each is 16 bytes of UTF-8 at most.
2. The camera answers `USER LOGONFAILED 3`, which carries a salt.
3. It sends a second `USER LOGON` with the base64 MD5 of the user name plus the first 8 bytes of the salt, and of the password plus the same 8 bytes.
4. The login ends at `<ip> IP INNER LOGON FINISHED`.

Any other `LOGONFAILED` reply, or a second request for a salt, raises `AuthError`. A wrong password on the I91FX gets `LOGONFAILED 2`.

A login step is any object with two methods (the `LoginStep` protocol in `sannce_aio.login`):

```python
from sannce_aio.login import LoginResult


class MyLogin:
    def first_fields(self, username: str, password: str) -> list[str]: ...

    def interpret_reply(self, fields: list[str]) -> LoginResult: ...
```

- `first_fields` returns the fields of the first message. The connection frames them and sends them on every connect and reconnect. `SaltedLogin(device_ip)` puts the camera address in the first field, and a custom step must do the same.
- `interpret_reply` gets the fields of each camera message, device address and route first. `LoginResult(success=True)` ends the login. `LoginResult(success=False, next_fields=[...])` sends one more message. Any other `success=False` means "not finished yet". A step raises `AuthError` to refuse the login. After 10 s without success the connection raises `ConnectError`.

Pass the step to the connection:

```python
import asyncio

from sannce_aio.connection import NvsConnection


async def main() -> None:
    connection = NvsConnection(
        "192.168.1.10", 3002, MyLogin(), on_event=print, on_availability=print
    )
    await connection.connect("admin", "PASSWORD")
    try:
        await asyncio.sleep(60)
    finally:
        await connection.close()


asyncio.run(main())
```

`SannceCamera` has no `login` argument. It builds its own connection with `SaltedLogin`.

## CLI

```sh
python -m sannce_aio discover [--timeout SECONDS] [--json]
python -m sannce_aio probe HOST [--user USER] [--pass PASSWORD] [--nvs-port PORT]
                                [--http-port PORT] [--rtsp-port PORT]
                                [--duration SECONDS] [--no-light] [--json]
```

`discover` prints one line per camera, or `no cameras found`. The values here are made up:

```
ip=192.168.1.10 mac=00:00:5e:00:53:2a serial=SN0000000001 model=MODEL-X http_port=80 server_port=3000 channels=1
```

The camera sends its MAC in lower case with the octets in reverse order, and `discover` puts them back. The I91FX reports `server_port` 3000 although that port is closed. Ignore it and use the WebSocket port 3002.

`probe` connects, prints `info` and `caps`, switches the floodlight on and back, then prints events until Ctrl-C or `--duration`. It needs the RTSP port too: `connect()` asks it for the backchannel. Sample output, from the bench simulator, which serves RTSP:

```
info: model=unknown serial=unknown firmware=1.0.0 mac=unknown
caps: light_mode motion person siren siren_on_event speaker vehicle volume white_light
light: off -> on -> off
watching events
event: motion active channel=0
event: motion active channel=0
event: motion clear channel=0
```

- The light test toggles the floodlight and puts it back, in infrared, smart or color mode. In custom mode it prints `light: skipped in custom mode` (JSON `{"type": "light", "skipped": "custom mode"}`) and leaves the light alone, because the library cannot set custom mode back. Forcing the lamp on rewrites the camera's timed window to 00:00 to 23:59, as the Home Assistant floodlight does. The probe does not restore the window, so a window you set in the vendor app is lost. `--no-light` skips the test.
- `--json` prints one JSON object per line, and nothing when `discover` finds no camera. `probe` objects carry a `type`: `info`, `caps`, `light`, `watching` or `event`. `discover` objects hold the camera fields.
- Defaults: user `admin`, empty password, WebSocket port 3002, HTTP port 80, RTSP port 554.
- Exit code 0 on success, 1 on an error (message on stderr), 2 on bad arguments (usage on stderr), 130 on Ctrl-C.

## Simulator

`python -m sannce_aio simulate` runs `sannce_aio.simulator.CameraSimulator` as a fake camera. The bench in [`bench/`](https://github.com/Paol0B/ha-sannce/tree/master/bench) runs it in a container. It follows the same spec as the library, so it shows that the parts fit together, not that a camera behaves this way.

```sh
python -m sannce_aio simulate [--host HOST] [--nvs-port PORT] [--http-port PORT]
                              [--control-port PORT] [--rtsp-port PORT]
                              [--rtsp-upstream-port PORT] [--user USER]
                              [--pass PASSWORD] [--model MODEL] [--serial SERIAL]
                              [--mac MAC]
```

- Defaults: host `0.0.0.0`, WebSocket port 3002, HTTP port 80, control port 8099, user `admin`, password `admin123`, model `I91FW-SIM`, serial `SIM0000000001`, MAC `00:00:5E:00:53:01`.
- The private protocol runs over a WebSocket on `--nvs-port`, with the salted MD5 login and a new salt for each connection. The simulator sends an idle message every 10 s and repeats an active alarm every second until it stops, as the I91FX does.
- It answers the LAN search on UDP 3000 and 4000, on every address. It joins both search groups on the interface that `--host` names, or on any interface for `0.0.0.0`. `--model`, `--serial` and `--mac` go into that reply.
- `--rtsp-port` puts an RTSP front on that port. It asks for the Digest login, as the camera does, and takes TCP interleaved transport only. It relays video and audio from a local RTSP server, such as mediamtx, on `--rtsp-upstream-port` (default 8554). It adds a `sendonly` PCMA and PCMU backchannel track to the `DESCRIBE` reply, and records the audio a client sends on it. As on the I91FX, a second `SETUP` of the same track in one session gets `455 Method Not Valid in This State`, and the `Content-Base` and `a=control` URLs use the host of the request. Without `--rtsp-port` there is no RTSP, and `/talk-busy` and `/audio.wav` answer 404.
- Port 80 needs root outside a container. Docker lets any user bind it inside one.
- It prints one line when it is ready, then runs until Ctrl-C.

The control API takes and returns JSON over HTTP, with no login. Keep it off untrusted networks.

| Request | Effect |
|---|---|
| `GET /state` | light (lamp lit), light power, light mode, detection flags and sensitivity, sounds played as `[sample, action]` pairs, volume, siren on event, client count, whether a client is sending backchannel audio (`talking`), user and password |
| `POST /event {"kind", "active"}` | push an event. `kind` is `motion`, `vehicle`, `intrusion`, `line`, `tamper` or `video_loss`. `active` is true or false |
| `POST /settings {"light", "light_mode", "detection", "volume"}` | change any of them, as the vendor app would. `light` is true or false: true switches to color mode and lights the lamp, false returns the lamp to auto. `light_mode` is `infrared`, `smart` or `color`. `detection` is an object of `person`, `vehicle` and `motion` booleans, each optional. `volume` is a whole number from 0 to 100 |
| `POST /password {"password"}` | change the password that new logins must use. Open sessions stay |
| `POST /drop {"seconds"}` | refuse connections on the private protocol port only, for `seconds` (0 to 3600), like a reboot. Its open sessions close and HTTP sessions end, but the HTTP port keeps answering. The LAN search gets no answer |
| `POST /talk-busy {"busy"}` | refuse the backchannel `SETUP` with RTSP 453 while `busy` is true, as if another client held the channel |
| `GET /audio.wav` | the audio of the current or last backchannel session as 8 kHz mono 16-bit WAV |
| `POST /reset` | back to the start state |

Requests that change something answer 204. A bad body answers 400 with a one-line reason.

## Tests

```sh
pip install -e ".[dev]"
python -m pytest -q
```

The tests run against `sannce_aio.simulator.CameraSimulator`, a fake camera on localhost. They need no camera.

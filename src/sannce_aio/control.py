from typing import Any

from aiohttp import web

from .simulator import CameraSimulator, event_fields

_SIMULATOR = web.AppKey("simulator", CameraSimulator)
_AUTO = 0
_MANUAL_ON = 1
_LIGHT_MODES = {"infrared": 1, "smart": 2, "color": 3}
# 4 is the vendor app's custom fill: readable, not settable (protocol.md, Light mode)
_MODE_NAMES = {1: "infrared", 2: "smart", 3: "color", 4: "custom"}
_DETECTION = ("person", "vehicle", "motion")
_SETTINGS = {"light", "light_mode", "detection"}
_MAX_DROP_SECONDS = 3600


def control_app(simulator: CameraSimulator) -> web.Application:
    app = web.Application()
    app[_SIMULATOR] = simulator
    app.add_routes(
        [
            web.get("/state", _state),
            web.post("/event", _event),
            web.post("/settings", _settings),
            web.post("/password", _password),
            web.post("/drop", _drop),
            web.post("/talk-busy", _talk_busy),
            web.get("/audio.wav", _audio),
            web.post("/reset", _reset),
        ]
    )
    return app


async def start_control(
    simulator: CameraSimulator, host: str, port: int
) -> web.AppRunner:
    runner = web.AppRunner(control_app(simulator), access_log=None)
    await runner.setup()
    try:
        await web.TCPSite(runner, host, port).start()
    except BaseException:
        await runner.cleanup()
        raise
    return runner


async def _state(request: web.Request) -> web.Response:
    simulator = request.app[_SIMULATOR]
    return web.json_response(
        {
            "light": simulator.light_control == _MANUAL_ON,
            "light_mode": _MODE_NAMES.get(simulator.light_mode),
            "detection": dict(simulator.detection),
            "clients": simulator.clients,
            "talking": simulator.talking,
            "user": simulator.username,
            "password": simulator.password,
        }
    )


async def _event(request: web.Request) -> web.Response:
    body = await _body(request)
    try:
        fields = event_fields(_text(body, "kind"), _flag(body, "active"))
    except ValueError as err:
        raise web.HTTPBadRequest(text=str(err)) from None
    await request.app[_SIMULATOR].push_event(fields)
    return web.Response(status=204)


async def _settings(request: web.Request) -> web.Response:
    body = await _body(request)
    if not body or not set(body) <= _SETTINGS:
        raise web.HTTPBadRequest(text="settings take light, light_mode and detection")
    light = _flag(body, "light") if "light" in body else None
    mode = None
    if "light_mode" in body:
        mode = _LIGHT_MODES.get(_text(body, "light_mode"))
        if mode is None:
            raise web.HTTPBadRequest(text="light_mode is infrared, smart or color")
    detection = body.get("detection", {})
    if not isinstance(detection, dict) or not set(detection) <= set(_DETECTION):
        raise web.HTTPBadRequest(text="detection takes person, vehicle and motion")
    changes = {name: _flag(detection, name) for name in detection}
    simulator = request.app[_SIMULATOR]
    if light is not None:
        simulator.light_control = _MANUAL_ON if light else _AUTO
    if mode is not None:
        simulator.light_mode = mode
    simulator.detection.update(changes)
    return web.Response(status=204)


async def _password(request: web.Request) -> web.Response:
    request.app[_SIMULATOR].password = _text(await _body(request), "password")
    return web.Response(status=204)


async def _drop(request: web.Request) -> web.Response:
    seconds = (await _body(request)).get("seconds")
    # bool is an int: refuse true and false
    if (
        isinstance(seconds, bool)
        or not isinstance(seconds, int | float)
        or not 0 <= seconds <= _MAX_DROP_SECONDS
    ):
        raise web.HTTPBadRequest(
            text=f"seconds is a number from 0 to {_MAX_DROP_SECONDS}"
        )
    await request.app[_SIMULATOR].drop(seconds)
    return web.Response(status=204)


async def _talk_busy(request: web.Request) -> web.Response:
    request.app[_SIMULATOR].set_talk_busy(_flag(await _body(request), "busy"))
    return web.Response(status=204)


async def _audio(request: web.Request) -> web.Response:
    return web.Response(
        body=request.app[_SIMULATOR].talk_wav(), content_type="audio/wav"
    )


async def _reset(request: web.Request) -> web.Response:
    await request.app[_SIMULATOR].reset()
    return web.Response(status=204)


async def _body(request: web.Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except ValueError:
        raise web.HTTPBadRequest(text="the body is not JSON") from None
    if not isinstance(body, dict):
        raise web.HTTPBadRequest(text="the body is not a JSON object")
    return body


def _flag(body: dict[str, Any], name: str) -> bool:
    value = body.get(name)
    if not isinstance(value, bool):
        raise web.HTTPBadRequest(text=f"{name} is true or false")
    return value


def _text(body: dict[str, Any], name: str) -> str:
    value = body.get(name)
    if not isinstance(value, str) or not value:
        raise web.HTTPBadRequest(text=f"{name} is a non-empty string")
    return value

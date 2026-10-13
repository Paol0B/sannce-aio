import argparse
import asyncio
import dataclasses
import json
import os
import sys
from collections.abc import Callable
from typing import TextIO

from .camera import SannceCamera
from .control import start_control
from .discovery import discover
from .errors import SannceError
from .events import Event
from .simulator import (
    DEFAULT_MAC,
    DEFAULT_MODEL,
    DEFAULT_SERIAL,
    MAC_SHAPE,
    SEARCH_PORTS,
    CameraSimulator,
)

_EXIT_FAILED = 1
_EXIT_INTERRUPTED = 130
_MAX_PORT = 65535

_Emit = Callable[[dict[str, object] | None, str], None]


def build_parser() -> argparse.ArgumentParser:
    output = argparse.ArgumentParser(add_help=False)
    output.add_argument(
        "--json", action="store_true", help="print one JSON object per line"
    )

    parser = argparse.ArgumentParser(prog="python -m sannce_aio")
    commands = parser.add_subparsers(dest="command", required=True)

    probe = commands.add_parser(
        "probe",
        parents=[output],
        help="print a camera's info and caps, toggle its light, stream its events",
    )
    probe.add_argument("host", help="camera address")
    probe.add_argument("--user", default="admin", help="camera user (default: admin)")
    probe.add_argument(
        "--pass", dest="password", default="", help="camera password (default: empty)"
    )
    probe.add_argument(
        "--nvs-port",
        type=_port,
        default=3000,
        help="private protocol port (default: 3000)",
    )
    probe.add_argument(
        "--http-port", type=_port, default=80, help="HTTP port (default: 80)"
    )
    probe.add_argument(
        "--duration",
        type=float,
        metavar="SECONDS",
        help="stop watching events after SECONDS (default: until Ctrl-C)",
    )
    probe.add_argument(
        "--no-light", action="store_true", help="do not toggle the light"
    )
    probe.set_defaults(run=run_probe)

    find = commands.add_parser(
        "discover", parents=[output], help="list the cameras on the LAN"
    )
    find.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        metavar="SECONDS",
        help="how long to wait for replies (default: 3)",
    )
    find.set_defaults(run=run_discover)

    simulate = commands.add_parser(
        "simulate", help="run a simulated camera with a control API"
    )
    simulate.add_argument(
        "--host", default="0.0.0.0", help="address to listen on (default: 0.0.0.0)"
    )
    simulate.add_argument(
        "--nvs-port",
        type=_port,
        default=3000,
        help="private protocol port (default: 3000)",
    )
    simulate.add_argument(
        "--http-port", type=_port, default=80, help="HTTP port (default: 80)"
    )
    simulate.add_argument(
        "--control-port",
        type=_port,
        default=8099,
        help="control API port (default: 8099)",
    )
    simulate.add_argument(
        "--user", default="admin", help="camera user (default: admin)"
    )
    simulate.add_argument(
        "--pass",
        dest="password",
        default="admin123",
        help="camera password (default: admin123)",
    )
    simulate.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"model in the LAN search reply (default: {DEFAULT_MODEL})",
    )
    simulate.add_argument(
        "--serial",
        default=DEFAULT_SERIAL,
        help=f"serial in the LAN search reply (default: {DEFAULT_SERIAL})",
    )
    simulate.add_argument(
        "--mac",
        type=_mac,
        default=DEFAULT_MAC,
        help=f"MAC in the LAN search reply (default: {DEFAULT_MAC})",
    )
    simulate.set_defaults(run=run_simulate)
    return parser


async def run_probe(args: argparse.Namespace, out: TextIO | None = None) -> None:
    emit = _emitter(out, args.json)
    camera = SannceCamera(
        args.host,
        args.user,
        args.password,
        nvs_port=args.nvs_port,
        http_port=args.http_port,
    )
    # events can arrive as soon as the login ends, before connect() returns
    camera.subscribe(lambda event: _emit_event(emit, event))
    try:
        await camera.connect()
        info = dataclasses.asdict(camera.info)
        emit({"type": "info", **info}, f"info: {_pairs(info)}")
        caps = sorted(camera.caps)
        emit({"type": "caps", "caps": caps}, f"caps: {' '.join(caps)}")
        if "white_light" in camera.caps and not args.no_light:
            await _toggle_light(camera, emit)
        emit({"type": "watching"}, "watching events")
        await _wait(args.duration)
    finally:
        await camera.close()


async def run_discover(args: argparse.Namespace, out: TextIO | None = None) -> None:
    emit = _emitter(out, args.json)
    cameras = await discover(args.timeout)
    for camera in cameras:
        fields = dataclasses.asdict(camera)
        emit(fields, _pairs(fields))
    if not cameras:
        emit(None, "no cameras found")


async def run_simulate(args: argparse.Namespace, out: TextIO | None = None) -> None:
    stream = sys.stdout if out is None else out
    simulator = CameraSimulator(
        host=args.host,
        username=args.user,
        password=args.password,
        port=args.nvs_port,
        http_port=args.http_port,
        search_ports=SEARCH_PORTS,
        model=args.model,
        serial=args.serial,
        mac=args.mac,
    )
    await simulator.start()
    try:
        control = await start_control(simulator, args.host, args.control_port)
        try:
            search = " ".join(str(port) for port in simulator.search_ports)
            print(
                f"simulating {args.model} on {args.host}: nvs {simulator.port}, "
                f"http {simulator.http_port}, search {search}, "
                f"control {control.addresses[0][1]}",
                file=stream,
                flush=True,
            )
            await asyncio.Event().wait()
        finally:
            await control.cleanup()
    finally:
        await simulator.stop()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        asyncio.run(args.run(args))
    except (SannceError, ValueError, OSError) as exc:
        if isinstance(exc, BrokenPipeError):
            _discard_stdout()
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_FAILED
    except KeyboardInterrupt:
        return _EXIT_INTERRUPTED
    return 0


def _emitter(out: TextIO | None, as_json: bool) -> _Emit:
    stream = sys.stdout if out is None else out

    def emit(record: dict[str, object] | None, text: str) -> None:
        if as_json and record is None:
            return
        print(json.dumps(record) if as_json else text, file=stream, flush=True)

    return emit


def _emit_event(emit: _Emit, event: Event) -> None:
    state = "active" if event.active else "clear"
    emit(
        {"type": "event", **dataclasses.asdict(event)},
        f"event: {event.kind} {state} channel={event.channel}",
    )


async def _toggle_light(camera: SannceCamera, emit: _Emit) -> None:
    try:
        before, toggled, restored = await _toggle_and_restore(camera)
    except SannceError as exc:
        emit({"type": "light", "error": str(exc)}, f"light: error: {exc}")
        return
    states = " -> ".join("on" if on else "off" for on in (before, toggled, restored))
    emit(
        {"type": "light", "before": before, "toggled": toggled, "restored": restored},
        f"light: {states}",
    )


async def _toggle_and_restore(camera: SannceCamera) -> tuple[bool, bool, bool]:
    before = await camera.get_light()
    try:
        await camera.set_light(not before)
        toggled = await camera.get_light()
    finally:
        await camera.set_light(before)
    return before, toggled, await camera.get_light()


async def _wait(duration: float | None) -> None:
    if duration is None:
        await asyncio.Event().wait()
    else:
        await asyncio.sleep(duration)


def _pairs(fields: dict[str, object]) -> str:
    return " ".join(f"{name}={value or 'unknown'}" for name, value in fields.items())


def _port(text: str) -> int:
    try:
        port = int(text)
    except ValueError:
        port = 0
    if not 1 <= port <= _MAX_PORT:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a port from 1 to {_MAX_PORT}"
        )
    return port


def _mac(text: str) -> str:
    if not MAC_SHAPE.fullmatch(text):
        raise argparse.ArgumentTypeError(f"{text!r} is not a MAC like {DEFAULT_MAC}")
    return text


def _discard_stdout() -> None:
    # else the flush at exit fails too: a second error line and exit code 120
    os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())


if __name__ == "__main__":
    sys.exit(main())

import asyncio
import gc
import io
import json
import os
import re
import signal
import socket
import sys

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web

from sannce_aio import __main__ as cli
from sannce_aio import discovery
from sannce_aio.camera import SannceCamera
from sannce_aio.discovery import build_seek_request, parse_discovery_reply
from sannce_aio.errors import AuthError
from sannce_aio.simulator import CameraSimulator

from .rtsp_fake import FakeRtspCamera

pytestmark = pytest.mark.asyncio

MOTION_START = ["INNER", "ALARM", "MOTIONDETECT", "0", "1"]
MOTION_STOP = ["INNER", "ALARM", "MOTIONDETECT", "0", "0"]
CAPS = [
    "light_mode",
    "motion",
    "person",
    "siren",
    "siren_on_event",
    "speaker",
    "vehicle",
    "volume",
    "white_light",
]
CAMERA_LINE = (
    "ip=192.168.1.10 mac=00:00:5e:00:53:2a serial=SN0000000001 model=MODEL-X "
    "http_port=80 server_port=3000 channels=1"
)
OTHER_LINE = (
    "ip=192.168.1.10 mac=00:00:5e:00:53:2b serial=SN0000000002 model=MODEL-X "
    "http_port=80 server_port=3000 channels=1"
)
SPAWN_TIMEOUT = 20
READY = re.compile(
    r"simulating (\S+) on (\S+): nvs (\d+), http (\d+), search (\d+), control (\d+)"
)
NO_SIGINT = sys.platform == "win32" or signal.getsignal(signal.SIGINT) is signal.SIG_IGN


async def wait_until(predicate, timeout=3.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition was not met in time")


class NoLightSimulator(CameraSimulator):
    async def _get_light(self, request):
        raise web.HTTPNotFound()


class RefusingSimulator(CameraSimulator):
    async def _put_light(self, request):
        raise web.HTTPInternalServerError()


class EagerSimulator(CameraSimulator):
    async def _logon(self, session, fields):
        await super()._logon(session, fields)
        await session.send(MOTION_START)


class ClosingSimulator(CameraSimulator):
    async def _logon(self, session, fields):
        await session.ws.close()


class Responder(asyncio.DatagramProtocol):
    def __init__(self, replies, delay):
        self.replies = replies
        self.delay = delay
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        loop = asyncio.get_running_loop()
        for reply in self.replies:
            loop.call_later(self.delay, self.transport.sendto, reply, addr)


def probe_argv(simulator, rtsp, *extra, password=None):
    return [
        "probe",
        simulator.host,
        "--user",
        simulator.username,
        "--pass",
        simulator.password if password is None else password,
        "--nvs-port",
        str(simulator.port),
        "--http-port",
        str(simulator.http_port),
        "--rtsp-port",
        str(rtsp.port),
        *extra,
    ]


def probe_args(simulator, rtsp, *extra, password=None):
    argv = probe_argv(simulator, rtsp, *extra, password=password)
    return cli.build_parser().parse_args(argv)


async def probe_lines(simulator, rtsp, *extra):
    out = io.StringIO()
    args = probe_args(simulator, rtsp, "--duration", "0", *extra)
    await asyncio.wait_for(cli.run_probe(args, out), timeout=5)
    return out.getvalue().splitlines()


def records(out):
    return [json.loads(line) for line in out.getvalue().splitlines()]


async def read_until(stream, wanted):
    async for raw in stream:
        if raw.decode().rstrip("\n") == wanted:
            return
    raise AssertionError(f"output ended before {wanted!r}")


async def discover_lines(*flags, timeout=0.2):
    out = io.StringIO()
    argv = ["discover", "--timeout", str(timeout), *flags]
    await cli.run_discover(cli.build_parser().parse_args(argv), out)
    return out.getvalue().splitlines()


@pytest_asyncio.fixture
async def rtsp():
    camera = FakeRtspCamera()
    await camera.start()
    yield camera
    await camera.stop()


@pytest_asyncio.fixture
async def start_simulator():
    started = []

    async def start(kind):
        simulator = kind()
        await simulator.start()
        started.append(simulator)
        return simulator

    yield start
    for simulator in started:
        await simulator.stop()


@pytest_asyncio.fixture
async def spawn():
    processes = []

    async def start(*argv, stdout=asyncio.subprocess.PIPE):
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "sannce_aio",
            *argv,
            stdout=stdout,
            stderr=asyncio.subprocess.PIPE,
        )
        processes.append(process)
        return process

    yield start
    for process in processes:
        if process.returncode is None:
            process.kill()
        await process.wait()


@pytest_asyncio.fixture
async def start_probe(simulator, rtsp):
    tasks = []

    def start(*extra):
        out = io.StringIO()
        args = probe_args(simulator, rtsp, *extra)
        task = asyncio.create_task(cli.run_probe(args, out))
        tasks.append(task)
        return task, out

    yield start
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


@pytest_asyncio.fixture
async def lan(monkeypatch):
    transports = []

    async def answer_with(*replies, delay=0):
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: Responder(replies, delay), local_addr=("127.0.0.1", 0)
        )
        transports.append(transport)
        monkeypatch.setattr(
            discovery, "TARGETS", (transport.get_extra_info("sockname"),)
        )

    yield answer_with
    for transport in transports:
        transport.close()


@pytest.fixture
def camera_reply(examples):
    return bytes.fromhex(examples["discovery_reply"]["hex"])


@pytest.fixture
def other_reply(camera_reply):
    return camera_reply.replace(b"2a:53:00:5e:00:00", b"2b:53:00:5e:00:00").replace(
        b"SN0000000001", b"SN0000000002"
    )


async def test_probe_prints_info_and_caps(simulator, rtsp):
    lines = await probe_lines(simulator, rtsp)

    assert "info: model=unknown serial=unknown firmware=1.0.0 mac=unknown" in lines
    assert "caps: " + " ".join(CAPS) in lines


@pytest.mark.parametrize(
    ("lit", "expected"),
    [(False, "light: off -> on -> off"), (True, "light: on -> off -> on")],
)
async def test_probe_toggles_the_light_and_puts_it_back(simulator, rtsp, lit, expected):
    if lit:
        simulator.light_mode = 3
        simulator.light_control = 3
        simulator.light_on_time = "00:00:00"
        simulator.light_off_time = "23:59:00"
    start = (simulator.light_mode, simulator.light_control, simulator.lamp_on)

    lines = await probe_lines(simulator, rtsp)

    assert expected in lines
    assert (simulator.light_mode, simulator.light_control, simulator.lamp_on) == start


@pytest.mark.parametrize("control", [0, 3])
async def test_probe_skips_the_light_in_custom_mode(simulator, rtsp, control):
    simulator.light_mode = 4
    simulator.light_control = control
    simulator.light_on_time = "00:00:00"
    simulator.light_off_time = "23:59:00"
    start = (simulator.light_mode, simulator.light_control, simulator.lamp_on)

    text = await probe_lines(simulator, rtsp)
    as_json = [
        json.loads(line) for line in await probe_lines(simulator, rtsp, "--json")
    ]

    assert text[text.index("light: skipped in custom mode") + 1] == "watching events"
    assert {"type": "light", "skipped": "custom mode"} in as_json
    assert (simulator.light_mode, simulator.light_control, simulator.lamp_on) == start


async def test_probe_no_light_leaves_the_light_alone(simulator, rtsp):
    lines = await probe_lines(simulator, rtsp, "--no-light")

    assert not [line for line in lines if line.startswith("light")]


async def test_probe_skips_the_light_when_the_camera_has_none(start_simulator, rtsp):
    simulator = await start_simulator(NoLightSimulator)

    lines = await probe_lines(simulator, rtsp)

    assert "caps: " + " ".join(cap for cap in CAPS if cap != "white_light") in lines
    assert not [line for line in lines if line.startswith("light")]


async def test_probe_reports_a_refused_light_change_and_keeps_watching(
    start_simulator, rtsp
):
    simulator = await start_simulator(RefusingSimulator)

    lines = await probe_lines(simulator, rtsp)

    assert len([line for line in lines if line.startswith("light: error: ")]) == 1
    assert lines[-1] == "watching events"


async def test_probe_prints_pushed_events_once_watching(simulator, start_probe):
    _, out = start_probe()
    await wait_until(lambda: "watching events" in out.getvalue().splitlines())

    await simulator.push_event(MOTION_START)
    await simulator.push_event(MOTION_STOP)
    await wait_until(
        lambda: "event: motion clear channel=0" in out.getvalue().splitlines()
    )

    lines = out.getvalue().splitlines()
    assert lines[lines.index("watching events") + 1 :] == [
        "event: motion active channel=0",
        "event: motion clear channel=0",
    ]


async def test_probe_shows_an_event_sent_right_after_login(start_simulator, rtsp):
    simulator = await start_simulator(EagerSimulator)

    lines = await probe_lines(simulator, rtsp)

    assert "event: motion active channel=0" in lines


async def test_probe_json_prints_one_object_per_line(simulator, start_probe):
    _, out = start_probe("--json")
    await wait_until(lambda: {"type": "watching"} in records(out))

    event = {"type": "event", "kind": "motion", "active": True, "channel": 0}
    await simulator.push_event(MOTION_START)
    await wait_until(lambda: event in records(out))

    assert records(out) == [
        {
            "type": "info",
            "model": None,
            "serial": None,
            "firmware": "1.0.0",
            "mac": None,
        },
        {"type": "caps", "caps": CAPS},
        {"type": "light", "before": False, "toggled": True, "restored": False},
        {"type": "watching"},
        event,
    ]


async def test_probe_closes_the_connection_when_interrupted(simulator, start_probe):
    task, out = start_probe()
    await wait_until(lambda: "watching events" in out.getvalue().splitlines())
    assert simulator.clients == 1

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    await wait_until(lambda: simulator.clients == 0)


async def test_probe_releases_everything_when_login_fails(simulator, rtsp):
    leaks = []
    asyncio.get_running_loop().set_exception_handler(
        lambda _loop, context: leaks.append(context)
    )

    with pytest.raises(AuthError):
        await cli.run_probe(
            probe_args(simulator, rtsp, password="wrong"), io.StringIO()
        )
    gc.collect()

    assert leaks == []


async def test_module_entry_point_runs_the_probe(simulator, rtsp, spawn):
    process = await spawn(*probe_argv(simulator, rtsp, "--duration", "0"))

    stdout, stderr = await asyncio.wait_for(process.communicate(), SPAWN_TIMEOUT)

    assert process.returncode == 0
    assert stderr == b""
    assert "caps: " + " ".join(CAPS) in stdout.decode().splitlines()


@pytest.mark.skipif(NO_SIGINT, reason="SIGINT cannot be delivered here")
async def test_ctrl_c_closes_the_connection_and_exits_quietly(simulator, rtsp, spawn):
    process = await spawn(*probe_argv(simulator, rtsp))
    await asyncio.wait_for(
        read_until(process.stdout, "watching events"), SPAWN_TIMEOUT
    )
    assert simulator.clients == 1

    process.send_signal(signal.SIGINT)
    _, stderr = await asyncio.wait_for(process.communicate(), SPAWN_TIMEOUT)

    assert process.returncode == 130
    assert stderr == b""
    await wait_until(lambda: simulator.clients == 0)


async def test_main_prints_one_error_line_when_login_fails(simulator, rtsp, capsys):
    argv = probe_argv(simulator, rtsp, password="wrong")
    code = await asyncio.to_thread(cli.main, argv)

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert captured.err.startswith("error: ")
    assert captured.err.count("\n") == 1


async def test_main_prints_one_error_line_when_the_camera_closes_the_connection(
    start_simulator, rtsp, capsys
):
    simulator = await start_simulator(ClosingSimulator)

    code = await asyncio.to_thread(cli.main, probe_argv(simulator, rtsp))

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert captured.err == "error: the camera closed the connection during login\n"


async def test_a_closed_stdout_pipe_gives_one_error_line_and_exit_1(
    simulator, rtsp, spawn
):
    read_end, write_end = os.pipe()
    argv = probe_argv(simulator, rtsp, "--duration", "0")
    process = await spawn(*argv, stdout=write_end)
    os.close(write_end)
    os.close(read_end)

    _, stderr = await asyncio.wait_for(process.communicate(), SPAWN_TIMEOUT)

    lines = stderr.decode().splitlines()
    assert process.returncode == 1
    assert len(lines) == 1
    assert lines[0].startswith("error: ")


@pytest.mark.parametrize("flag", ["--nvs-port", "--http-port", "--rtsp-port"])
@pytest.mark.parametrize("port", ["0", "65536", "70000", "abc"])
async def test_main_exits_2_with_usage_for_a_bad_port(simulator, rtsp, capsys, flag, port):
    with pytest.raises(SystemExit) as stop:
        await asyncio.to_thread(cli.main, probe_argv(simulator, rtsp, flag, port))

    err = capsys.readouterr().err
    assert stop.value.code == 2
    assert err.startswith("usage: python -m sannce_aio probe")
    assert f"error: argument {flag}: " in err


async def test_probe_uses_rtsp_port_554_by_default():
    args = cli.build_parser().parse_args(["probe", "127.0.0.1"])

    assert args.rtsp_port == 554


async def test_ports_1_and_65535_are_accepted():
    argv = ["probe", "127.0.0.1", "--nvs-port", "1", "--http-port", "65535"]

    args = cli.build_parser().parse_args(argv)

    assert (args.nvs_port, args.http_port) == (1, 65535)


async def test_main_rejects_a_host_that_is_a_url(capsys):
    code = await asyncio.to_thread(cli.main, ["probe", "http://camera"])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.startswith("error: host")
    assert captured.err.count("\n") == 1


async def test_discover_prints_one_line_per_camera(lan, camera_reply):
    await lan(camera_reply)

    assert await discover_lines() == [CAMERA_LINE]


async def test_discover_json_prints_one_object_per_camera(lan, camera_reply):
    await lan(camera_reply)

    lines = await discover_lines("--json")

    assert [json.loads(line) for line in lines] == [
        {
            "ip": "192.168.1.10",
            "mac": "00:00:5e:00:53:2a",
            "serial": "SN0000000001",
            "model": "MODEL-X",
            "http_port": 80,
            "server_port": 3000,
            "channels": 1,
        }
    ]


@pytest.mark.parametrize(
    ("flags", "expected"),
    [([], ["no cameras found"]), (["--json"], [])],
    ids=["text", "json"],
)
async def test_discover_without_replies(lan, flags, expected):
    await lan()

    assert await discover_lines(*flags) == expected


async def test_discover_prints_every_camera_on_its_own_line(
    lan, camera_reply, other_reply
):
    await lan(camera_reply, other_reply)

    assert sorted(await discover_lines()) == [CAMERA_LINE, OTHER_LINE]


@pytest.mark.parametrize(("timeout", "listed"), [(1.0, True), (0.1, False)])
async def test_discover_timeout_decides_which_replies_count(
    lan, camera_reply, timeout, listed
):
    await lan(camera_reply, delay=0.5)

    lines = await discover_lines(timeout=timeout)

    assert (CAMERA_LINE in lines) is listed


async def test_main_runs_discover(lan, camera_reply, capsys):
    await lan(camera_reply)

    code = await asyncio.to_thread(cli.main, ["discover", "--timeout", "0.2"])

    assert code == 0
    assert capsys.readouterr().out.splitlines() == [CAMERA_LINE]


class SeekReceiver(asyncio.DatagramProtocol):
    def __init__(self):
        self.replies = asyncio.Queue()

    def datagram_received(self, data, addr):
        self.replies.put_nowait((data, addr))


@pytest_asyncio.fixture
async def simulate(monkeypatch):
    monkeypatch.setattr(cli, "SEARCH_PORTS", (0,))
    tasks = []

    async def start(*argv):
        args = cli.build_parser().parse_args(["simulate", "--host", "127.0.0.1", *argv])
        args.nvs_port = args.http_port = args.control_port = 0
        if args.rtsp_port is not None:
            args.rtsp_port = 0
        out = io.StringIO()
        task = asyncio.create_task(cli.run_simulate(args, out))
        tasks.append(task)
        await wait_until(lambda: READY.search(out.getvalue()))
        return task, READY.search(out.getvalue())

    yield start
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def test_simulate_answers_on_the_ports_discovery_asks():
    assert cli.SEARCH_PORTS is discovery.SEARCH_PORTS
    assert discovery.SEARCH_PORTS == (3000, 4000)


async def test_simulate_defaults():
    args = cli.build_parser().parse_args(["simulate"])

    assert (args.host, args.nvs_port, args.http_port, args.control_port) == (
        "0.0.0.0",
        3002,
        80,
        8099,
    )
    assert (args.rtsp_port, args.rtsp_upstream_port) == (None, 8554)
    assert (args.user, args.password) == ("admin", "admin123")
    assert (args.model, args.serial, args.mac) == (
        "I91FW-SIM",
        "SIM0000000001",
        "00:00:5E:00:53:01",
    )


@pytest.mark.parametrize(
    "mac", ["", "00:00:5E:00:53", "00-00-5E-00-53-01", "00:00:5E:00:53:0G"]
)
async def test_simulate_rejects_a_mac_of_the_wrong_shape(capsys, mac):
    with pytest.raises(SystemExit) as stop:
        cli.build_parser().parse_args(["simulate", "--mac", mac])

    assert stop.value.code == 2
    assert "error: argument --mac: " in capsys.readouterr().err


async def test_simulate_serves_the_camera_and_its_control_api(simulate):
    _, ready = await simulate(
        "--pass", "secret", "--model", "CAM-SIM", "--rtsp-port", "1"
    )
    model, host, nvs, http, _, control = ready.groups()
    camera = SannceCamera(
        host,
        "admin",
        "secret",
        nvs_port=int(nvs),
        http_port=int(http),
        rtsp_port=rtsp_port(ready),
    )

    try:
        await camera.connect()
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://{host}:{control}/state") as reply:
                state = await reply.json()
    finally:
        await camera.close()

    assert (model, host) == ("CAM-SIM", "127.0.0.1")
    assert (state["clients"], state["password"]) == (1, "secret")


def rtsp_port(ready):
    return int(re.search(r"rtsp (\d+)$", ready.string.strip()).group(1))


async def test_simulate_serves_rtsp_when_asked(simulate):
    _, ready = await simulate("--rtsp-port", "1")
    host, control = ready.group(2), ready.group(6)
    rtsp = rtsp_port(ready)

    reader, writer = await asyncio.open_connection(host, rtsp)
    try:
        writer.write(b"OPTIONS rtsp://x/1/1 RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        reply = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
    finally:
        writer.close()
    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://{host}:{control}/audio.wav") as response:
            audio = response.status

    assert reply.startswith(b"RTSP/1.0 401")
    assert audio == 200


async def test_simulate_has_no_rtsp_by_default(simulate):
    _, ready = await simulate()
    host, control = ready.group(2), ready.group(6)

    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://{host}:{control}/audio.wav") as response:
            audio = response.status

    assert "rtsp" not in ready.string
    assert audio == 404


async def test_simulate_closes_the_rtsp_port_when_cancelled(simulate):
    task, ready = await simulate("--rtsp-port", "1")
    host = ready.group(2)
    rtsp = rtsp_port(ready)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    with pytest.raises(ConnectionRefusedError):
        await asyncio.open_connection(host, rtsp)


async def test_simulate_answers_the_lan_search(simulate):
    _, ready = await simulate("--serial", "SN-SIM")
    _, host, nvs, http, search, _ = ready.groups()
    loop = asyncio.get_running_loop()
    transport, receiver = await loop.create_datagram_endpoint(
        SeekReceiver, local_addr=("127.0.0.1", 0)
    )

    try:
        transport.sendto(build_seek_request(), (host, int(search)))
        data, source = await asyncio.wait_for(receiver.replies.get(), 2)
    finally:
        transport.close()

    found = parse_discovery_reply(data, source[0])
    assert (found.ip, found.serial, found.server_port, found.http_port) == (
        "127.0.0.1",
        "SN-SIM",
        int(nvs),
        int(http),
    )


async def test_simulate_closes_its_ports_when_cancelled(simulate):
    task, ready = await simulate()
    _, host, nvs, _, _, control = ready.groups()

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    for port in (nvs, control):
        with pytest.raises(ConnectionRefusedError):
            await asyncio.open_connection(host, int(port))


async def test_main_prints_one_error_line_when_a_simulate_port_is_taken(capsys):
    with socket.socket() as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen()
        port = holder.getsockname()[1]
        argv = ["simulate", "--host", "127.0.0.1", "--nvs-port", str(port)]

        code = await asyncio.to_thread(cli.main, argv)

    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.startswith("error: ")
    assert str(port) in captured.err
    assert captured.err.count("\n") == 1


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


async def test_main_prints_one_error_line_when_the_rtsp_port_is_taken(capsys, monkeypatch):
    monkeypatch.setattr(cli, "SEARCH_PORTS", (0,))
    with socket.socket() as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen()
        port = holder.getsockname()[1]
        argv = [
            "simulate", "--host", "127.0.0.1", "--nvs-port", str(free_port()),
            "--http-port", str(free_port()), "--control-port", str(free_port()),
            "--rtsp-port", str(port),
        ]

        code = await asyncio.to_thread(cli.main, argv)

    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.startswith("error: ")
    assert str(port) in captured.err
    assert captured.err.count("\n") == 1

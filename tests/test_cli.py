import asyncio
import gc
import io
import json
import signal
import sys

import pytest
import pytest_asyncio
from aiohttp import web

from sannce_aio import __main__ as cli
from sannce_aio import discovery
from sannce_aio.errors import AuthError
from sannce_aio.simulator import CameraSimulator

pytestmark = pytest.mark.asyncio

MOTION_START = ["INNER", "ALARM", "MOTIONDETECT", "0", "1"]
MOTION_STOP = ["INNER", "ALARM", "MOTIONDETECT", "0", "0"]
CAPS = ["light_mode", "motion", "person", "talk", "vehicle", "white_light"]
CAMERA_LINE = (
    "ip=192.168.1.10 mac=00:00:5E:00:53:2A serial=SN0000000001 model=MODEL-X "
    "http_port=80 server_port=3000 channels=1"
)
OTHER_LINE = (
    "ip=192.168.1.10 mac=00:00:5E:00:53:2B serial=SN0000000002 model=MODEL-X "
    "http_port=80 server_port=3000 channels=1"
)
SPAWN_TIMEOUT = 20
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


def probe_argv(simulator, *extra, password=None):
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
        *extra,
    ]


def probe_args(simulator, *extra, password=None):
    argv = probe_argv(simulator, *extra, password=password)
    return cli.build_parser().parse_args(argv)


async def probe_lines(simulator, *extra):
    out = io.StringIO()
    args = probe_args(simulator, "--duration", "0", *extra)
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

    async def start(*argv):
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "sannce_aio",
            *argv,
            stdout=asyncio.subprocess.PIPE,
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
async def start_probe(simulator):
    tasks = []

    def start(*extra):
        out = io.StringIO()
        task = asyncio.create_task(cli.run_probe(probe_args(simulator, *extra), out))
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
    return camera_reply.replace(b"2A:53:00:5E:00:00", b"2B:53:00:5E:00:00").replace(
        b"SN0000000001", b"SN0000000002"
    )


async def test_probe_prints_info_and_caps(simulator):
    lines = await probe_lines(simulator)

    assert "info: model=unknown serial=unknown firmware=1.0.0 mac=unknown" in lines
    assert "caps: " + " ".join(CAPS) in lines


@pytest.mark.parametrize(
    ("initial", "expected"),
    [(0, "light: off -> on -> off"), (1, "light: on -> off -> on")],
)
async def test_probe_toggles_the_light_and_puts_it_back(simulator, initial, expected):
    simulator.light_control = initial

    lines = await probe_lines(simulator)

    assert expected in lines
    assert simulator.light_control == initial


async def test_probe_no_light_leaves_the_light_alone(simulator):
    lines = await probe_lines(simulator, "--no-light")

    assert not [line for line in lines if line.startswith("light")]


async def test_probe_skips_the_light_when_the_camera_has_none(start_simulator):
    simulator = await start_simulator(NoLightSimulator)

    lines = await probe_lines(simulator)

    assert "caps: light_mode motion person talk vehicle" in lines
    assert not [line for line in lines if line.startswith("light")]


async def test_probe_reports_a_refused_light_change_and_keeps_watching(
    start_simulator,
):
    simulator = await start_simulator(RefusingSimulator)

    lines = await probe_lines(simulator)

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


async def test_probe_shows_an_event_sent_right_after_login(start_simulator):
    simulator = await start_simulator(EagerSimulator)

    lines = await probe_lines(simulator)

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


async def test_probe_releases_everything_when_login_fails(simulator):
    leaks = []
    asyncio.get_running_loop().set_exception_handler(
        lambda _loop, context: leaks.append(context)
    )

    with pytest.raises(AuthError):
        await cli.run_probe(probe_args(simulator, password="wrong"), io.StringIO())
    gc.collect()

    assert leaks == []


async def test_module_entry_point_runs_the_probe(simulator, spawn):
    process = await spawn(*probe_argv(simulator, "--duration", "0"))

    stdout, stderr = await asyncio.wait_for(process.communicate(), SPAWN_TIMEOUT)

    assert process.returncode == 0
    assert stderr == b""
    assert "caps: " + " ".join(CAPS) in stdout.decode().splitlines()


@pytest.mark.skipif(NO_SIGINT, reason="SIGINT cannot be delivered here")
async def test_ctrl_c_closes_the_connection_and_exits_quietly(simulator, spawn):
    process = await spawn(*probe_argv(simulator))
    await asyncio.wait_for(
        read_until(process.stdout, "watching events"), SPAWN_TIMEOUT
    )
    assert simulator.clients == 1

    process.send_signal(signal.SIGINT)
    _, stderr = await asyncio.wait_for(process.communicate(), SPAWN_TIMEOUT)

    assert process.returncode == 130
    assert stderr == b""
    await wait_until(lambda: simulator.clients == 0)


async def test_main_prints_one_error_line_when_login_fails(simulator, capsys):
    code = await asyncio.to_thread(cli.main, probe_argv(simulator, password="wrong"))

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert captured.err.startswith("error: ")
    assert captured.err.count("\n") == 1


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
            "mac": "00:00:5E:00:53:2A",
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

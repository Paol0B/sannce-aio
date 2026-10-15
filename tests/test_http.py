import asyncio
import hashlib
import re
import socket
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web

from sannce_aio.errors import AuthError, ConnectError, ProtocolError
from sannce_aio.http import Detection, HttpClient, LightState

pytestmark = pytest.mark.asyncio

USER = "admin"
PASSWORD = "secret"
XML = "application/xml; charset=utf-8"
SESSION_CHECK = "/CGI/Security/SessionCheck"
LOGON = "/CGI/Security/Logon"
USER_CHECK = "/ISAPI/Security/userCheck"
REALM = "sannce-test"
NONCE = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
# sha256sum of "adminsecret", then 3 rounds of sha256sum of h + "K3Y", uppercase hex
LOGON_PASSWD = "6EF5F3771EF6A42DBDB46DCCBF0905B15647A26AA3D6488ED2DEB0DB35EA6865"
USER_CHECK_OK = (
    "<userCheck><statusValue>200</statusValue><statusString>OK</statusString>"
    "<passwdLeftValue>5</passwdLeftValue></userCheck>"
)
WRITE_OK = (
    "<ResponseStatus><statusCode>1</statusCode>"
    "<statusString>OK</statusString></ResponseStatus>"
)
EMPTY_FAR_LAMP = (
    "<infraredFarLampPower>100</infraredFarLampPower>",
    "<infraredFarLampPower/>",
)
EXTRA_DETECTION = (
    "<regionType>grid</regionType>"
    "<Grid><rowGranularity>18</rowGranularity>"
    "<columnGranularity>22</columnGranularity></Grid>"
    "<MotionDetectionLayout><sensitivityLevel>60</sensitivityLevel>"
    "<layout><gridMap>FFFC00</gridMap></layout></MotionDetectionLayout>"
)


WHITE_LIGHT = (
    '<WhiteLight><contrltype opt="0,2,3">2</contrltype>'
    "<sunRiseTime>07:00:00</sunRiseTime><sunSetTime>17:00:00</sunSetTime>"
    "<infraredLampPower>60</infraredLampPower>"
    "<infraredFarLampPower>60</infraredFarLampPower></WhiteLight>"
)
FORCED_ON = (
    '<WhiteLight><contrltype opt="0,2,3">3</contrltype>'
    "<sunRiseTime>23:59:00</sunRiseTime><sunSetTime>00:00:00</sunSetTime>"
    "<infraredLampPower>40</infraredLampPower>"
    "<infraredFarLampPower>40</infraredFarLampPower></WhiteLight>"
)
GUARD_SOUND_CAPS = (
    "<ChanBasicCapList><capTypeList><capType>guardSound</capType><support>true</support>"
    "<subCap><supportSoundSampleNum>3</supportSoundSampleNum>"
    "<supportSoundCustomNum>2</supportSoundCustomNum></subCap></capTypeList></ChanBasicCapList>"
)
VMD_TRIGGER = (
    "<EventTrigger><id>VMD</id><enabled>true</enabled><eventType></eventType>"
    "<EventTriggerNotificationList><EventTriggerNotification><id>whiteLampForBody</id>"
    "<notificationMethod>whiteLampForBody</notificationMethod></EventTriggerNotification>"
    "</EventTriggerNotificationList></EventTrigger>"
)
TWO_WAY_AUDIO = (
    "<TwoWayAudioChannel><id>1</id>"
    '<audioCompressionType opt="G.711A,G.711U">G.711A</audioCompressionType>'
    "<speakerVolume>80</speakerVolume><enabled>true</enabled>"
    '<audioOutputType opt="close,innerspeaker">innerspeaker</audioOutputType>'
    "<outputVolume>80</outputVolume></TwoWayAudioChannel>"
)
LIGHT = "/ISAPI/Image/channels/1/WhiteLight"
PLAY_AUDIO = "/CGI/Event/PlayAudio"
VMD = "/ISAPI/Event/triggers/VMD/channels/1"
AUDIO = "/ISAPI/System/TwoWayAudio/channels/1"
DETECTION = "/ISAPI/System/Video/inputs/channels/1/motionDetection"
CAPS = "/CGI/System/channels/1/capabilities"


def put_body(camera, path):
    return ET.fromstring(
        next(s.body for s in reversed(camera.sent("PUT")) if s.path == path)
    )


@dataclass(frozen=True)
class Example:
    method: str
    path: str
    status: int | None
    headers: dict
    body: str


def load(examples, example_id):
    example = examples[example_id]
    head, _, body = example["text"].partition("\r\n\r\n")
    start, *lines = head.split("\r\n")
    headers = dict(line.split(": ", 1) for line in lines)
    if start.startswith("HTTP/"):
        fields = example["fields"]
        status = int(start.split()[1])
        return Example(fields["method"], fields["path"], status, headers, body)
    method, path, _ = start.split(" ")
    return Example(method, path, None, headers, body)


def edit(text, *changes):
    for old, new in changes:
        assert old in text
        text = text.replace(old, new)
    return text


@dataclass
class Seen:
    method: str
    path: str
    target: str
    query: dict
    headers: object
    body: str


class FakeCamera:
    def __init__(self, auth):
        self.auth = auth
        self.log = []
        self.authorized = []
        self.replies = {}
        self.session_check = (404, "") if auth != "session" else None
        self.checks = 0
        self.logons = 0
        self.valid_session = None
        self.logon_override = None
        self.denied_status = 401
        self.password = PASSWORD
        self.hold_user_check = False
        self.echo_writes = False
        self.user_check_seen = asyncio.Event()
        self.release = asyncio.Event()
        self.port = None
        self.app = web.Application()
        self.app.router.add_route("*", "/{path:.*}", self.handle)

    def serve(self, method, path, body, status=200):
        self.replies[(method, path)] = (status, body)

    def serve_reply(self, example):
        self.serve(example.method, example.path, example.body, example.status)

    def sent(self, method):
        return [seen for seen in self.authorized if seen.method == method]

    async def handle(self, request):
        seen = Seen(
            request.method,
            request.path,
            request.raw_path,
            dict(request.query),
            request.headers,
            await request.text(),
        )
        self.log.append(seen)
        if seen.path == SESSION_CHECK:
            return self.session_check_reply()
        if seen.path == LOGON:
            return self.logon_reply(seen)
        if not self.allows(seen):
            return self.denied()
        self.authorized.append(seen)
        if seen.path == USER_CHECK and self.hold_user_check:
            self.user_check_seen.set()
            await self.release.wait()
        if self.echo_writes:
            if seen.method == "PUT":
                self.serve("GET", seen.path, seen.body)
            else:
                await asyncio.sleep(0.01)
        return self.reply(*self.replies.get((seen.method, seen.path), (404, "")))

    def session_check_reply(self):
        self.checks += 1
        if self.session_check is not None:
            return self.reply(*self.session_check)
        return self.reply(
            200,
            f"<SessionCheck><session>TMP-{self.checks}</session>"
            "<key>K3Y</key><iterations>3</iterations></SessionCheck>",
        )

    def logon_reply(self, seen):
        status, session = self.logon_override or self.check_logon(seen)
        return self.reply(
            200,
            f"<UserLogon><statusString>{status}</statusString>"
            "<statusValue>200</statusValue><passwdLeftValue>5</passwdLeftValue>"
            f"<session>{session}</session></UserLogon>",
        )

    def check_logon(self, seen):
        fields = {child.tag: child.text for child in ET.fromstring(seen.body)}
        accepted = fields == {
            "passwd": LOGON_PASSWD,
            "sessionTmp": f"TMP-{self.checks}",
            "username": USER,
        }
        if not accepted:
            return "PASSWD ERROR", ""
        self.logons += 1
        self.valid_session = f"SESSION-{self.logons}"
        return "OK", self.valid_session

    def allows(self, seen):
        if self.auth == "session":
            return (
                self.valid_session is not None
                and seen.headers.get("HttpSession") == self.valid_session
            )
        return self.auth == "none" or self.digest_valid(seen)

    def digest_valid(self, seen):
        header = seen.headers.get("Authorization", "")
        if not header.startswith("Digest "):
            return False
        pairs = re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]*))', header)
        fields = {key: quoted or bare for key, quoted, bare in pairs}

        def md5(text):
            return hashlib.md5(text.encode()).hexdigest()

        ha1 = md5(f"{USER}:{REALM}:{self.password}")
        ha2 = md5(f"{seen.method}:{fields.get('uri')}")
        response = md5(
            f"{ha1}:{fields.get('nonce')}:{fields.get('nc')}:"
            f"{fields.get('cnonce')}:{fields.get('qop')}:{ha2}"
        )
        return (
            fields.get("username") == USER
            and fields.get("nonce") == NONCE
            and fields.get("uri") == seen.target
            and fields.get("response") == response
        )

    def denied(self):
        headers = {}
        if self.auth == "digest":
            challenge = f'Digest realm="{REALM}", nonce="{NONCE}", qop="auth"'
            headers["WWW-Authenticate"] = challenge
        return web.Response(status=self.denied_status, headers=headers)

    @staticmethod
    def reply(status, body):
        data = body.encode() if isinstance(body, str) else body
        return web.Response(
            status=status, body=data, content_type="application/xml", charset="utf-8"
        )


@pytest_asyncio.fixture
async def start_camera():
    runners = []

    async def start(auth="session", host="127.0.0.1"):
        fake = FakeCamera(auth)
        runner = web.AppRunner(fake.app)
        await runner.setup()
        runners.append(runner)
        await web.TCPSite(runner, host, 0).start()
        fake.port = runner.addresses[0][1]
        return fake

    yield start
    for runner in runners:
        await runner.cleanup()


@pytest_asyncio.fixture
async def make_client():
    clients = []

    def make(port, password=PASSWORD, host="127.0.0.1", **kwargs):
        client = HttpClient(host, USER, password, port=port, **kwargs)
        clients.append(client)
        return client

    yield make
    for client in clients:
        await client.close()


@pytest_asyncio.fixture
async def camera(start_camera):
    return await start_camera()


@pytest_asyncio.fixture
async def client(camera, make_client):
    return make_client(camera.port)


async def test_get_light_parses_example(examples, camera, client):
    camera.serve_reply(load(examples, "http_whitelight_get_reply"))

    state = await client.get_light()

    assert state == LightState(
        control=0,
        options=(0, 1, 2, 3),
        power=100,
        far_power=100,
        on_time="18:00:00",
        off_time="06:00:00",
    )


async def test_release_light_returns_to_auto(examples, camera, client):
    get = load(examples, "http_whitelight_get_reply")
    put = load(examples, "http_whitelight_set_manual_on")
    camera.serve_reply(get)
    camera.serve(put.method, put.path, WRITE_OK)

    await client.release_light()

    (sent,) = camera.sent("PUT")
    assert (sent.method, sent.path) == (put.method, put.path)
    assert sent.headers["Content-Type"] == put.headers["Content-Type"]
    assert sent.body == edit(put.body, ("<contrltype>1<", "<contrltype>0<"))


async def test_release_light_echoes_values_from_the_last_read(examples, camera, client):
    get = load(examples, "http_whitelight_get_reply")
    put = load(examples, "http_whitelight_set_manual_on")
    changes = [
        ("<infraredFarLampPower>100<", "<infraredFarLampPower>60<"),
        ("<infraredLampPower>100<", "<infraredLampPower>40<"),
        ("<sunRiseTime>06:00:00<", "<sunRiseTime>07:30:00<"),
        ("<sunSetTime>18:00:00<", "<sunSetTime>17:45:00<"),
    ]
    camera.serve("GET", get.path, edit(get.body, *changes))
    camera.serve(put.method, put.path, WRITE_OK)

    await client.release_light()

    (sent,) = camera.sent("PUT")
    assert sent.body == edit(put.body, ("<contrltype>1<", "<contrltype>0<"), *changes)


async def test_release_light_omits_times_the_camera_did_not_send(examples, camera, client):
    get = load(examples, "http_whitelight_get_reply")
    put = load(examples, "http_whitelight_set_manual_on")
    changes = [
        ("<sunRiseTime>06:00:00</sunRiseTime>", ""),
        ("<sunSetTime>18:00:00</sunSetTime>", ""),
    ]
    camera.serve("GET", get.path, edit(get.body, *changes))
    camera.serve(put.method, put.path, WRITE_OK)

    await client.release_light()

    (sent,) = camera.sent("PUT")
    assert sent.body == edit(put.body, ("<contrltype>1<", "<contrltype>0<"), *changes)


async def test_get_light_reads_an_empty_lamp_element_as_missing(
    examples, camera, client
):
    get = load(examples, "http_whitelight_get_reply")
    camera.serve("GET", get.path, edit(get.body, EMPTY_FAR_LAMP))

    state = await client.get_light()

    assert (state.far_power, state.power) == (None, 100)


async def test_release_light_leaves_out_an_empty_lamp_element(examples, camera, client):
    get = load(examples, "http_whitelight_get_reply")
    put = load(examples, "http_whitelight_set_manual_on")
    camera.serve("GET", get.path, edit(get.body, EMPTY_FAR_LAMP))
    camera.serve(put.method, put.path, WRITE_OK)

    await client.release_light()

    (sent,) = camera.sent("PUT")
    assert sent.body == edit(
        put.body, ("<contrltype>1<", "<contrltype>0<"), (EMPTY_FAR_LAMP[0], "")
    )


async def test_set_light_mode_smart_sends_example_body(examples, camera, client):
    put = load(examples, "http_light_mode_set_smart")
    camera.serve(put.method, put.path, WRITE_OK)

    await client.set_light_mode("smart")

    (sent,) = camera.sent("PUT")
    assert (sent.method, sent.path, sent.body) == (put.method, put.path, put.body)
    assert sent.headers["Content-Type"] == put.headers["Content-Type"]


@pytest.mark.parametrize(("mode", "value"), [("infrared", "1"), ("color", "3")])
async def test_set_light_mode_other_values(examples, camera, client, mode, value):
    put = load(examples, "http_light_mode_set_smart")
    camera.serve(put.method, put.path, WRITE_OK)

    await client.set_light_mode(mode)

    (sent,) = camera.sent("PUT")
    assert sent.body == edit(put.body, ("<value>2<", f"<value>{value}<"))


async def test_set_light_mode_rejects_unknown_mode(camera, client):
    with pytest.raises(ValueError, match="night"):
        await client.set_light_mode("night")

    assert camera.log == []


@pytest.mark.parametrize(
    ("value", "mode"),
    [("1", "infrared"), ("2", "smart"), ("3", "color"), ("4", "custom")],
)
async def test_get_light_mode_names_the_value(examples, camera, client, value, mode):
    sample = load(examples, "http_light_mode_set_smart")
    body = edit(sample.body, ("<value>2<", f"<value>{value}<"))
    camera.serve("GET", sample.path, body)

    assert await client.get_light_mode() == mode


async def test_get_light_mode_rejects_undocumented_value(examples, camera, client):
    sample = load(examples, "http_light_mode_set_smart")
    camera.serve("GET", sample.path, edit(sample.body, ("<value>2<", "<value>9<")))

    with pytest.raises(ProtocolError, match="9"):
        await client.get_light_mode()


async def test_get_detection_parses_example(examples, camera, client):
    camera.serve_reply(load(examples, "http_motion_detection_get_reply"))

    assert await client.get_detection() == Detection(
        person=True, vehicle=True, motion=False
    )


async def test_flags_missing_from_the_reply_read_as_off(examples, camera, client):
    get = load(examples, "http_motion_detection_get_reply")
    body = edit(
        get.body,
        ("<allEnabled>false</allEnabled>", ""),
        ("<carEnabled>true</carEnabled>", ""),
    )
    camera.serve("GET", get.path, body)

    assert await client.get_detection() == Detection(
        person=True, vehicle=False, motion=False
    )


@pytest.mark.parametrize(
    ("flags", "changes"),
    [
        ({"person": False}, [("<enabled>true<", "<enabled>false<")]),
        ({"vehicle": False}, [("<carEnabled>true<", "<carEnabled>false<")]),
        ({"motion": True}, [("<allEnabled>false<", "<allEnabled>true<")]),
        (
            {"person": False, "vehicle": False, "motion": True},
            [
                ("<enabled>true<", "<enabled>false<"),
                ("<carEnabled>true<", "<carEnabled>false<"),
                ("<allEnabled>false<", "<allEnabled>true<"),
            ],
        ),
    ],
)
async def test_set_detection_writes_only_the_given_flags(
    examples, camera, client, flags, changes
):
    get = load(examples, "http_motion_detection_get_reply")
    camera.serve_reply(get)
    camera.serve("PUT", get.path, WRITE_OK)

    await client.set_detection(**flags)

    (sent,) = camera.sent("PUT")
    assert (sent.method, sent.path) == ("PUT", get.path)
    assert sent.body == edit(get.body, *changes)
    assert sent.headers["Content-Type"] == XML


async def test_set_detection_sends_back_elements_it_does_not_know(
    examples, camera, client
):
    get = load(examples, "http_motion_detection_get_reply")
    end = "</MotionDetection>"
    body = edit(get.body, (end, EXTRA_DETECTION + end))
    camera.serve("GET", get.path, body)
    camera.serve("PUT", get.path, WRITE_OK)

    await client.set_detection(person=False)

    (sent,) = camera.sent("PUT")
    assert sent.body == edit(body, ("<enabled>true<", "<enabled>false<"))


async def test_set_detection_writes_a_flag_the_reply_left_out(examples, camera, client):
    get = load(examples, "http_motion_detection_get_reply")
    end = "</MotionDetection>"
    body = edit(get.body, ("<allEnabled>false</allEnabled>", ""))
    camera.serve("GET", get.path, body)
    camera.serve("PUT", get.path, WRITE_OK)

    await client.set_detection(motion=True)

    (sent,) = camera.sent("PUT")
    assert sent.body == edit(body, (end, "<allEnabled>true</allEnabled>" + end))


async def test_detection_and_sensitivity_writes_keep_both_changes(
    examples, camera, client
):
    get = load(examples, "http_motion_detection_get_reply")
    camera.serve_reply(get)
    camera.serve("PUT", get.path, WRITE_OK)
    camera.echo_writes = True

    await asyncio.gather(
        client.set_detection(person=False), client.set_sensitivity(50)
    )

    detection = await client.get_detection()
    assert (detection.person, detection.sensitivity) == (False, 50)


async def test_set_detection_without_flags_sends_nothing(camera, client):
    await client.set_detection()

    assert camera.log == []


async def test_detection_refusal_names_the_sub_status(examples, camera, client):
    get = load(examples, "http_motion_detection_get_reply")
    camera.serve_reply(get)
    camera.serve(
        "PUT",
        get.path,
        "<ResponseStatus><statusCode>4</statusCode><statusString>Failed</statusString>"
        "<subStatusCode>vcaPerformanceLimit</subStatusCode></ResponseStatus>",
    )

    with pytest.raises(ProtocolError, match="vcaPerformanceLimit"):
        await client.set_detection(person=True)


@pytest.mark.parametrize(
    "reply",
    [
        "<ResponseStatus><statusCode>4</statusCode></ResponseStatus>",
        "<ResponseStatus><statusString>Invalid</statusString></ResponseStatus>",
    ],
)
async def test_refused_write_raises_protocol_error(examples, camera, client, reply):
    get = load(examples, "http_whitelight_get_reply")
    camera.serve_reply(get)
    camera.serve("PUT", get.path, reply)

    with pytest.raises(ProtocolError):
        await client.release_light()


@pytest.mark.parametrize("reply", ["", "OK"])
async def test_write_accepts_a_2xx_reply_without_a_status_document(
    examples, camera, client, reply
):
    get = load(examples, "http_whitelight_get_reply")
    camera.serve_reply(get)
    camera.serve("PUT", get.path, reply)

    await client.release_light()

    assert len(camera.sent("PUT")) == 1


async def test_get_capabilities_parses_example(examples, camera, client):
    reply = load(examples, "http_capabilities_reply")
    camera.serve_reply(reply)

    caps = await client.get_capabilities()

    assert caps == {"person": True, "vehicle": True, "motion": True}
    (sent,) = camera.sent("POST")
    assert (sent.method, sent.path) == (reply.method, reply.path)
    assert sent.body == examples["http_capabilities_reply"]["fields"]["request_body"]
    assert sent.headers["Content-Type"] == XML


@pytest.mark.parametrize(
    ("changes", "caps"),
    [
        (
            [("<supportType>car</supportType><supportType>all</supportType>", "")],
            {"person": True, "vehicle": False, "motion": False},
        ),
        (
            [
                ("<supportType>people</supportType>", ""),
                ("<supportType>all</supportType>", ""),
            ],
            {"person": False, "vehicle": True, "motion": False},
        ),
        (
            [("<support>true<", "<support>false<")],
            {"person": False, "vehicle": False, "motion": False},
        ),
        (
            [
                (
                    "<supportType>people</supportType><supportType>car</supportType>"
                    "<supportType>all</supportType>",
                    "",
                )
            ],
            {"person": False, "vehicle": False, "motion": False},
        ),
    ],
    ids=["person-only", "vehicle-only", "support-false", "empty-list"],
)
async def test_get_capabilities_lists_only_what_is_reported(
    examples, camera, client, changes, caps
):
    reply = load(examples, "http_capabilities_reply")
    camera.serve("POST", reply.path, edit(reply.body, *changes))

    assert await client.get_capabilities() == caps


@pytest.mark.parametrize(
    ("call", "method", "path", "source"),
    [
        (
            "get_light",
            "GET",
            "/ISAPI/Image/channels/2/WhiteLight",
            "http_whitelight_get_reply",
        ),
        (
            "get_light_mode",
            "GET",
            "/CGI/System/CommonEnable/channels/2/Type/4120",
            "http_light_mode_set_smart",
        ),
        (
            "get_detection",
            "GET",
            "/ISAPI/System/Video/inputs/channels/2/motionDetection",
            "http_motion_detection_get_reply",
        ),
        (
            "get_capabilities",
            "POST",
            "/CGI/System/channels/2/capabilities",
            "http_capabilities_reply",
        ),
    ],
)
async def test_channel_selects_the_read_path(
    examples, camera, client, call, method, path, source
):
    camera.serve(method, path, load(examples, source).body)

    await getattr(client, call)(channel=2)

    assert [(seen.method, seen.path) for seen in camera.authorized] == [(method, path)]


@pytest.mark.parametrize(
    ("call", "kwargs", "read", "path"),
    [
        (
            "release_light",
            {},
            "http_whitelight_get_reply",
            "/ISAPI/Image/channels/2/WhiteLight",
        ),
        (
            "set_light_mode",
            {"mode": "smart"},
            None,
            "/CGI/System/CommonEnable/channels/2/Type/4120",
        ),
        (
            "set_detection",
            {"person": False},
            "http_motion_detection_get_reply",
            "/ISAPI/System/Video/inputs/channels/2/motionDetection",
        ),
    ],
)
async def test_channel_selects_the_write_path(
    examples, camera, client, call, kwargs, read, path
):
    if read:
        camera.serve("GET", path, load(examples, read).body)
    camera.serve("PUT", path, WRITE_OK)

    await getattr(client, call)(channel=2, **kwargs)

    assert [seen.path for seen in camera.sent("PUT")] == [path]


@pytest.mark.parametrize(
    ("call", "kwargs"),
    [
        ("get_light", {}),
        ("release_light", {}),
        ("get_light_mode", {}),
        ("set_light_mode", {"mode": "smart"}),
        ("get_detection", {}),
        ("set_detection", {"person": True}),
        ("get_capabilities", {}),
    ],
)
async def test_channel_below_one_is_rejected_before_any_request(
    camera, client, call, kwargs
):
    with pytest.raises(ValueError, match="channel"):
        await getattr(client, call)(channel=0, **kwargs)

    assert camera.log == []


async def test_session_login_comes_first(examples, camera, client):
    get = load(examples, "http_whitelight_get_reply")
    camera.serve_reply(get)

    await client.get_light()

    assert [(seen.method, seen.path) for seen in camera.log] == [
        ("GET", SESSION_CHECK),
        ("POST", LOGON),
        ("GET", get.path),
    ]
    check, logon, read = camera.log
    assert "Authorization" not in check.headers
    assert "HttpSession" not in check.headers
    assert PASSWORD not in logon.body
    assert read.headers["HttpSession"] == "SESSION-1"
    assert "Authorization" not in read.headers


async def test_refused_logon_raises_auth_error_without_a_digest_retry(
    camera, make_client
):
    client = make_client(camera.port, password="wrong")

    with pytest.raises(AuthError):
        await client.get_light()

    assert [(seen.method, seen.path) for seen in camera.log] == [
        ("GET", SESSION_CHECK),
        ("POST", LOGON),
    ]


@pytest.mark.parametrize("override", [("PASSWD ERROR", "SESSION-9"), ("OK", "")])
async def test_logon_needs_an_ok_status_and_a_session(camera, client, override):
    camera.logon_override = override

    with pytest.raises(AuthError):
        await client.get_light()

    assert [(seen.method, seen.path) for seen in camera.log] == [
        ("GET", SESSION_CHECK),
        ("POST", LOGON),
    ]


@pytest.mark.parametrize(
    "session_check",
    [
        (404, ""),
        (401, ""),
        (200, "<html><body>login</body></html>"),
        (200, "<SessionCheck><session>TMP-1</session></SessionCheck>"),
    ],
)
async def test_digest_is_used_when_session_check_fails(
    examples, start_camera, make_client, session_check
):
    camera = await start_camera("digest")
    camera.session_check = session_check
    get = load(examples, "http_whitelight_get_reply")
    camera.serve_reply(get)
    camera.serve("GET", USER_CHECK, USER_CHECK_OK)
    client = make_client(camera.port)

    state = await client.get_light()

    assert state.control == 0
    first = camera.log[0]
    assert first.path == SESSION_CHECK
    assert "Authorization" not in first.headers
    assert [seen.path for seen in camera.authorized] == [USER_CHECK, get.path]
    assert camera.authorized[0].query == {"username": USER, "passwd": PASSWORD}
    assert all("HttpSession" not in seen.headers for seen in camera.log)


async def test_camera_without_login_works_through_user_check(
    examples, start_camera, make_client
):
    camera = await start_camera("none")
    get = load(examples, "http_whitelight_get_reply")
    camera.serve_reply(get)
    camera.serve("GET", USER_CHECK, USER_CHECK_OK)
    client = make_client(camera.port)

    state = await client.get_light()

    assert state.control == 0
    assert [seen.path for seen in camera.log] == [SESSION_CHECK, USER_CHECK, get.path]
    assert all("Authorization" not in seen.headers for seen in camera.log)


async def test_digest_with_a_wrong_password_raises_auth_error(
    start_camera, make_client
):
    camera = await start_camera("digest")
    camera.serve("GET", USER_CHECK, USER_CHECK_OK)
    client = make_client(camera.port, password="wrong")

    with pytest.raises(AuthError):
        await client.get_light()

    assert camera.authorized == []


async def test_failed_digest_login_is_retried_on_the_next_call(
    examples, start_camera, make_client
):
    camera = await start_camera("digest")
    get = load(examples, "http_whitelight_get_reply")
    camera.serve_reply(get)
    camera.serve("GET", USER_CHECK, "", 500)
    client = make_client(camera.port)
    with pytest.raises(ProtocolError):
        await client.get_light()
    camera.serve("GET", USER_CHECK, USER_CHECK_OK)

    await client.get_light()

    assert [seen.path for seen in camera.authorized] == [
        USER_CHECK,
        USER_CHECK,
        get.path,
    ]


async def test_cancelled_digest_login_is_retried_on_the_next_call(
    examples, start_camera, make_client
):
    camera = await start_camera("digest")
    get = load(examples, "http_whitelight_get_reply")
    camera.serve_reply(get)
    camera.serve("GET", USER_CHECK, USER_CHECK_OK)
    camera.hold_user_check = True
    client = make_client(camera.port)
    call = asyncio.create_task(client.get_light())
    await camera.user_check_seen.wait()
    call.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call
    camera.release.set()

    await client.get_light()

    assert [seen.path for seen in camera.authorized] == [
        USER_CHECK,
        USER_CHECK,
        get.path,
    ]


async def test_digest_login_needs_an_ok_status(start_camera, make_client):
    camera = await start_camera("digest")
    refused = edit(USER_CHECK_OK, ("<statusString>OK<", "<statusString>BAD<"))
    camera.serve("GET", USER_CHECK, refused)
    client = make_client(camera.port)

    with pytest.raises(AuthError):
        await client.get_light()


@pytest.mark.parametrize("denied", [401, 403])
async def test_expired_session_logs_in_again(examples, camera, client, denied):
    camera.denied_status = denied
    get = load(examples, "http_whitelight_get_reply")
    camera.serve_reply(get)
    await client.get_light()
    camera.valid_session = None

    await client.get_light()

    assert [(seen.method, seen.path) for seen in camera.log[3:]] == [
        ("GET", get.path),
        ("GET", SESSION_CHECK),
        ("POST", LOGON),
        ("GET", get.path),
    ]
    assert camera.log[-1].headers["HttpSession"] == "SESSION-2"


async def test_concurrent_calls_log_in_once(examples, camera, client):
    camera.serve_reply(load(examples, "http_whitelight_get_reply"))

    await asyncio.gather(client.get_light(), client.get_light(), client.get_light())

    assert [seen.path for seen in camera.log].count(LOGON) == 1


async def test_unreachable_camera_raises_connect_error(make_client):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        unused = probe.getsockname()[1]
    client = make_client(unused)

    with pytest.raises(ConnectError):
        await client.get_light()


@pytest.mark.parametrize(
    "body",
    [
        "",
        "not xml",
        "<Other/>",
        "<WhiteLight></WhiteLight>",
        "<WhiteLight><contrltype>x</contrltype></WhiteLight>",
        "<WhiteLight><contrltype>0</contrltype>"
        "<infraredLampPower>bright</infraredLampPower></WhiteLight>",
    ],
)
async def test_unreadable_reply_raises_protocol_error(examples, camera, client, body):
    path = load(examples, "http_whitelight_get_reply").path
    camera.serve("GET", path, body)

    with pytest.raises(ProtocolError):
        await client.get_light()


@pytest.mark.parametrize(
    ("call", "source"),
    [
        ("get_detection", "http_motion_detection_get_reply"),
        ("get_capabilities", "http_capabilities_reply"),
    ],
)
async def test_reply_with_another_root_raises_protocol_error(
    examples, camera, client, call, source
):
    sample = load(examples, source)
    camera.serve(sample.method, sample.path, WRITE_OK)

    with pytest.raises(ProtocolError):
        await getattr(client, call)()


@pytest.mark.parametrize("status", [404, 500])
async def test_error_status_raises_protocol_error(examples, camera, client, status):
    path = load(examples, "http_whitelight_get_reply").path
    camera.serve("GET", path, "", status)

    with pytest.raises(ProtocolError, match=str(status)):
        await client.get_light()


@pytest.mark.parametrize(
    "wrap",
    [
        lambda body: b"\xef\xbb\xbf" + body.encode(),
        lambda body: b'<?xml version="1.0" encoding="UTF-8"?>' + body.encode(),
        lambda body: body.replace(
            "<WhiteLight>", '<WhiteLight xmlns="http://camera.invalid/ver20/XMLSchema">'
        ).encode(),
    ],
    ids=["byte-order-mark", "declaration", "namespace"],
)
async def test_reply_variants_still_parse(examples, camera, client, wrap):
    get = load(examples, "http_whitelight_get_reply")
    camera.serve("GET", get.path, wrap(get.body))

    state = await client.get_light()

    assert state.control == 0
    assert state.on_time == "18:00:00"


async def test_user_check_query_carries_reserved_characters(
    examples, start_camera, make_client
):
    password = "p&ss w+rd#%"
    camera = await start_camera("digest")
    camera.password = password
    camera.serve_reply(load(examples, "http_whitelight_get_reply"))
    camera.serve("GET", USER_CHECK, USER_CHECK_OK)
    client = make_client(camera.port, password=password)

    await client.get_light()

    assert camera.authorized[0].query == {"username": USER, "passwd": password}


async def test_ipv6_host_is_bracketed_in_the_url(examples, start_camera, make_client):
    try:
        camera = await start_camera(host="::1")
    except OSError:
        pytest.skip("no IPv6 loopback")
    camera.serve_reply(load(examples, "http_whitelight_get_reply"))
    client = make_client(camera.port, host="::1")

    state = await client.get_light()

    assert state.control == 0


async def test_given_session_carries_the_requests_and_stays_open(
    examples, camera, make_client
):
    camera.serve_reply(load(examples, "http_whitelight_get_reply"))
    async with aiohttp.ClientSession(headers={"X-Probe": "shared"}) as shared:
        client = make_client(camera.port, session=shared)

        await client.get_light()
        await client.close()

        assert not shared.closed
    assert all(seen.headers.get("X-Probe") == "shared" for seen in camera.log)


async def test_close_closes_the_session_it_created(
    examples, camera, make_client, monkeypatch
):
    closed = []
    close = aiohttp.ClientSession.close

    async def spy(session):
        closed.append(session)
        await close(session)

    monkeypatch.setattr(aiohttp.ClientSession, "close", spy)
    camera.serve_reply(load(examples, "http_whitelight_get_reply"))
    client = make_client(camera.port)

    await client.get_light()
    await client.close()

    assert len(closed) == 1


async def test_forced_on_is_the_full_day_timed_window(camera, client):
    camera.serve("GET", LIGHT, FORCED_ON)
    assert (await client.get_light()).forced_on is True


async def test_an_ordinary_timed_window_is_not_forced_on(camera, client):
    camera.serve("GET", LIGHT, FORCED_ON.replace("00:00:00", "18:00:00"))
    assert (await client.get_light()).forced_on is False


async def test_force_light_on_writes_the_full_day_window_and_power(camera, client):
    camera.serve("PUT", LIGHT, WRITE_OK)

    await client.force_light_on(40)

    body = put_body(camera, LIGHT)
    assert {child.tag: child.text for child in body} == {
        "contrltype": "3",
        "infraredFarLampPower": "40",
        "infraredLampPower": "40",
        "sunRiseTime": "23:59:00",
        "sunSetTime": "00:00:00",
    }


@pytest.mark.parametrize("power", [0, 101])
async def test_force_light_on_rejects_power_out_of_range(client, power):
    with pytest.raises(ValueError):
        await client.force_light_on(power)


async def test_force_light_on_reports_a_refusal(camera, client):
    camera.serve(
        "PUT", LIGHT,
        "<ResponseStatus><statusCode>3</statusCode><statusString>Device Error</statusString>"
        "<subStatusCode>deviceError</subStatusCode></ResponseStatus>",
    )
    with pytest.raises(ProtocolError, match="Device Error"):
        await client.force_light_on(100)


async def test_release_light_writes_auto_and_keeps_the_rest(camera, client):
    camera.serve("GET", LIGHT, WHITE_LIGHT)
    camera.serve("PUT", LIGHT, WRITE_OK)

    await client.release_light()

    body = put_body(camera, LIGHT)
    assert body.findtext("contrltype") == "0"
    assert body.findtext("infraredLampPower") == "60"
    assert body.find("contrltype").get("opt") is None


async def test_get_sound_count_reads_the_guard_sound_capability(camera, client):
    camera.serve("POST", CAPS, GUARD_SOUND_CAPS)
    assert await client.get_sound_count() == 3


async def test_get_sound_count_is_zero_without_support(camera, client):
    camera.serve("POST", CAPS, GUARD_SOUND_CAPS.replace("<support>true", "<support>false"))
    assert await client.get_sound_count() == 0


@pytest.mark.parametrize(("call", "action"), [("play_sound", "1"), ("stop_sound", "0")])
async def test_sound_calls_put_play_audio(camera, client, call, action):
    camera.serve("PUT", PLAY_AUDIO, WRITE_OK)

    await getattr(client, call)(2)

    body = put_body(camera, PLAY_AUDIO)
    assert [(c.tag, c.text) for c in body] == [
        ("channelID", "1"), ("type", "0"), ("sampleNo", "2"), ("action", action),
    ]


async def test_play_sound_rejects_a_negative_sample(client):
    with pytest.raises(ValueError):
        await client.play_sound(-1)


async def test_siren_on_event_reads_the_guard_sound_link(camera, client):
    camera.serve("GET", VMD, VMD_TRIGGER)
    assert await client.get_siren_on_event() is False


async def test_set_siren_on_event_adds_the_link_and_keeps_the_others(camera, client):
    camera.serve("GET", VMD, VMD_TRIGGER)
    camera.serve("PUT", VMD, WRITE_OK)

    await client.set_siren_on_event(True)

    links = put_body(camera, VMD).findall("EventTriggerNotificationList/EventTriggerNotification")
    assert [(n.findtext("id"), n.findtext("notificationMethod"), n.findtext("SoundID")) for n in links] == [
        ("whiteLampForBody", "whiteLampForBody", None),
        ("guardsound-1", "guardsound", "1"),
    ]


async def test_set_siren_on_event_off_removes_only_the_guard_sound(camera, client):
    linked = VMD_TRIGGER.replace(
        "</EventTriggerNotificationList>",
        "<EventTriggerNotification><id>guardsound-2</id><notificationMethod>guardsound"
        "</notificationMethod><SoundID>2</SoundID></EventTriggerNotification>"
        "</EventTriggerNotificationList>",
    )
    camera.serve("GET", VMD, linked)
    camera.serve("PUT", VMD, WRITE_OK)

    await client.set_siren_on_event(False)

    links = put_body(camera, VMD).findall("EventTriggerNotificationList/EventTriggerNotification")
    assert [n.findtext("id") for n in links] == ["whiteLampForBody"]


async def test_set_siren_on_event_adds_a_missing_link_list(camera, client):
    camera.serve("GET", VMD, "<EventTrigger><id>VMD</id></EventTrigger>")
    camera.serve("PUT", VMD, WRITE_OK)

    await client.set_siren_on_event(True)

    links = put_body(camera, VMD).findall("EventTriggerNotificationList/EventTriggerNotification")
    assert [n.findtext("id") for n in links] == ["guardsound-1"]


async def test_volume_reads_output_volume(camera, client):
    camera.serve("GET", AUDIO, TWO_WAY_AUDIO)
    assert await client.get_volume() == 80


async def test_set_volume_writes_the_whole_document_without_options(camera, client):
    camera.serve("GET", AUDIO, TWO_WAY_AUDIO)
    camera.serve("PUT", AUDIO, WRITE_OK)

    await client.set_volume(30)

    body = put_body(camera, AUDIO)
    assert body.findtext("outputVolume") == "30"
    assert body.findtext("speakerVolume") == "80"
    assert all("opt" not in node.attrib for node in body.iter())


async def test_volume_without_output_volume_raises_protocol_error(camera, client):
    camera.serve("GET", AUDIO, "<TwoWayAudioChannel><id>1</id></TwoWayAudioChannel>")
    with pytest.raises(ProtocolError, match="outputVolume"):
        await client.get_volume()


@pytest.mark.parametrize("volume", [-1, 101])
async def test_set_volume_rejects_out_of_range(client, volume):
    with pytest.raises(ValueError):
        await client.set_volume(volume)


@pytest.mark.parametrize("level", [-1, 101])
async def test_set_sensitivity_rejects_out_of_range(client, level):
    with pytest.raises(ValueError):
        await client.set_sensitivity(level)


async def test_detection_reads_the_sensitivity(camera, client):
    camera.serve(
        "GET", DETECTION,
        "<MotionDetection><enabled>true</enabled><carEnabled>true</carEnabled>"
        f"<allEnabled>false</allEnabled>{EXTRA_DETECTION}</MotionDetection>",
    )
    assert (await client.get_detection()).sensitivity == 60


async def test_set_sensitivity_keeps_the_grid(camera, client):
    camera.serve(
        "GET", DETECTION,
        f"<MotionDetection><enabled>true</enabled>{EXTRA_DETECTION}</MotionDetection>",
    )
    camera.serve("PUT", DETECTION, WRITE_OK)

    await client.set_sensitivity(90)

    body = put_body(camera, DETECTION)
    assert body.findtext("MotionDetectionLayout/sensitivityLevel") == "90"
    assert body.findtext("MotionDetectionLayout/layout/gridMap") == "FFFC00"

import ast
import inspect
import re
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

import sannce_aio
from sannce_aio import __main__ as cli

LIB = Path(__file__).resolve().parents[1]
README = LIB / "README.md"
PUBLIC_NAMES = {
    "AuthError",
    "CameraInfo",
    "ConnectError",
    "Detection",
    "DiscoveredCamera",
    "Event",
    "ProtocolError",
    "SannceCamera",
    "SannceError",
    "TalkBusyError",
    "discover",
    "find_camera",
}


@pytest.fixture(scope="module")
def pyproject():
    return tomllib.loads((LIB / "pyproject.toml").read_text(encoding="utf-8"))


def read_readme():
    return README.read_text(encoding="utf-8")


def imported_modules(source_file):
    for node in ast.walk(ast.parse(source_file.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            yield node.module


def test_all_is_the_public_api():
    assert set(sannce_aio.__all__) == PUBLIC_NAMES


@pytest.mark.parametrize("name", sorted(PUBLIC_NAMES))
def test_public_name_resolves(name):
    assert hasattr(sannce_aio, name)


def test_entry_points_have_the_documented_kind():
    assert inspect.isclass(sannce_aio.SannceCamera)
    assert inspect.iscoroutinefunction(sannce_aio.discover)
    assert inspect.iscoroutinefunction(sannce_aio.find_camera)


def test_project_identity(pyproject):
    project = pyproject["project"]
    assert project["name"] == "sannce-aio"
    assert str(Version(project["version"])) == project["version"]
    assert project["description"].strip()
    assert project["requires-python"] == ">=3.11"


def test_runtime_dependency_is_aiohttp_only(pyproject):
    requirements = [Requirement(text) for text in pyproject["project"]["dependencies"]]
    assert [requirement.name for requirement in requirements] == ["aiohttp"]
    assert not requirements[0].specifier.contains("3.11.99")


def test_sources_import_only_the_standard_library_and_aiohttp():
    allowed = sys.stdlib_module_names | {"aiohttp", "sannce_aio"}
    unexpected = {
        f"{path.name}: {module}"
        for path in (LIB / "src" / "sannce_aio").glob("*.py")
        for module in imported_modules(path)
        if module.split(".")[0] not in allowed
    }
    assert unexpected == set()


def test_dev_extra_has_the_test_tools(pyproject):
    extra = pyproject["project"]["optional-dependencies"]["dev"]
    assert {Requirement(text).name for text in extra} == {"pytest", "pytest-asyncio"}


def test_wheel_packages_the_source_tree(pyproject):
    assert pyproject["build-system"]["build-backend"] == "hatchling.build"
    wheel = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert wheel["packages"] == ["src/sannce_aio"]
    assert (LIB / "src" / "sannce_aio" / "__init__.py").is_file()


def test_the_package_ships_type_information():
    assert (LIB / "src" / "sannce_aio" / "py.typed").is_file()


def test_readme_is_declared_and_exists(pyproject):
    assert pyproject["project"]["readme"] == "README.md"
    assert README.is_file()


def test_readme_names_every_public_export():
    text = read_readme()
    missing = [
        name for name in sorted(PUBLIC_NAMES) if not re.search(rf"\b{name}\b", text)
    ]
    assert missing == []


@pytest.mark.parametrize("command", ["probe", "discover", "simulate"])
def test_readme_documents_the_cli_command_and_its_flags(command, capsys):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([command, "--help"])
    flags = set(re.findall(r"--[a-z][a-z-]*", capsys.readouterr().out)) - {"--help"}
    text = read_readme()
    assert f"python -m sannce_aio {command}" in text
    assert [flag for flag in sorted(flags) if flag not in text] == []


def test_readme_links_resolve():
    targets = re.findall(r"\]\((?!https?:)([^)#]+)", read_readme())
    assert targets
    assert [target for target in targets if not (LIB / target).exists()] == []

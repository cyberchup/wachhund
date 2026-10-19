"""requirements.txt is the hashed lock generated from requirements.in; check that they agree."""

import re

from repo import ROOT

PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)", re.MULTILINE)


def pins(name: str) -> dict[str, str]:
    """Package (normalized as pip compares names) -> pinned version."""
    text = (ROOT / name).read_text(encoding="utf-8")
    return {re.sub(r"[-_.]+", "-", package).lower(): version for package, version in PIN.findall(text)}


def test_lock_pins_each_direct_dependency_at_its_version():
    # A pin changed in only one file, by hand or by Dependabot, fails here. Regenerate the
    # lock with the command at the top of requirements.txt.
    direct = pins("requirements.in")
    locked = pins("requirements.txt")
    assert direct
    assert {package: locked.get(package) for package in direct} == direct


def test_every_locked_package_has_a_hash():
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    entries = re.split(r"\n(?=[A-Za-z0-9])", text.split("\n", 2)[2])
    assert entries and all("--hash=sha256:" in entry for entry in entries)

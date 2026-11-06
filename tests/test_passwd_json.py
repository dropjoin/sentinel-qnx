import dataclasses
import json
from pathlib import Path

from sentinel.cli import main
from sentinel.rules import audit_files

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_passwd_findings():
    findings = audit_files({"passwd": (SAMPLES / "passwd").read_text(),
                            "s.sh": (SAMPLES / "clean-startup.sh").read_text()})
    ids = {f.rule_id for f in findings}
    assert "EMPTY_PASSWORD" in ids
    assert "EXTRA_UID0" in ids


def test_json_mode_shape(capsys=None):
    rc = main(["audit", "--json", str(SAMPLES / "flawed-startup.sh")])
    assert rc == 1

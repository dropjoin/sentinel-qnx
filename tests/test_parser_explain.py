from pathlib import Path

from sentinel.buildfile import parse_buildfile, world_writable
from sentinel.explain import narrative
from sentinel.rules import audit_files

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def load(name):
    return (SAMPLES / name).read_text()


def test_parser_extracts_attrs():
    entries = parse_buildfile(load("flawed.build"))
    cfg = next(e for e in entries if e.target == "data/app-config")
    assert cfg.attrs.get("perms") == "0777"
    assert cfg.source == "./config/app-config.json"


def test_world_writable_octal_and_symbolic():
    assert world_writable("0777") and world_writable("0666")
    assert not world_writable("0755") and not world_writable("0644")
    assert world_writable("o+w")


def test_buildfile_rule_fires_only_on_flawed():
    bad = audit_files({"img.build": load("flawed.build"),
                       "s.sh": load("clean-startup.sh")})
    assert any(f.rule_id == "WORLD_WRITABLE_FILE" for f in bad)
    good = audit_files({"img.build": load("clean.build"),
                        "s.sh": load("clean-startup.sh")})
    assert not any(f.rule_id == "WORLD_WRITABLE_FILE" for f in good)


def test_narrative_mentions_impact_and_order():
    findings = audit_files({"startup.sh": load("flawed-startup.sh")})
    text = narrative(findings)
    assert "Executive summary" in text
    assert "Impact scenario" in text

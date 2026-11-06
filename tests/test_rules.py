from pathlib import Path

from sentinel.rules import audit_files

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def load(name):
    return (SAMPLES / name).read_text()


def test_flawed_set_flags_everything():
    findings = audit_files({
        "startup.sh": load("flawed-startup.sh"),
        "manifest.txt": load("flawed-manifest.txt"),
    })
    ids = {f.rule_id for f in findings}
    assert "DEBUG_SHELL" in ids
    assert "PERMISSIVE_MODE" in ids
    assert "VULN_COMPONENT" in ids
    assert "NO_ADAPTIVE_PARTITIONING" in ids
    assert any(f.severity == "CRITICAL" for f in findings)


def test_clean_set_is_quiet():
    findings = audit_files({
        "startup.sh": load("clean-startup.sh"),
        "manifest.txt": load("clean-manifest.txt"),
    })
    assert findings == []


def test_finding_has_location_and_patch():
    findings = audit_files({"startup.sh": load("flawed-startup.sh")})
    shell = next(f for f in findings if f.rule_id == "DEBUG_SHELL")
    assert shell.line == 3
    assert shell.patch

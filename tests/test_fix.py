from pathlib import Path

from sentinel.fix import fix_text
from sentinel.rules import audit_files

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def load(name):
    return (SAMPLES / name).read_text()


def test_fix_startup_removes_critical_and_high():
    fixed = fix_text("startup.sh", load("flawed-startup.sh"))
    findings = audit_files({"startup.sh": fixed,
                            "m.txt": load("clean-manifest.txt")})
    ids = {f.rule_id for f in findings}
    assert "DEBUG_SHELL" not in ids
    assert "PERMISSIVE_MODE" not in ids


def test_fix_buildfile_clears_world_writable():
    fixed = fix_text("img.build", load("flawed.build"))
    assert "perms=0755" in fixed or "perms=0754" in fixed
    findings = audit_files({"img.build": fixed,
                            "s.sh": load("clean-startup.sh")})
    assert not any(f.rule_id == "WORLD_WRITABLE_FILE" for f in findings)


def test_fix_never_touches_components():
    fixed = fix_text("manifest.txt", load("flawed-manifest.txt"))
    assert "openssl = 1.0.2" in fixed  # upgrades are human decisions

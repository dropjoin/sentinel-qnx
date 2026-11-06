from pathlib import Path

from sentinel.rules import audit_files

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def load(name):
    return (SAMPLES / name).read_text()


def test_flawed_sshd_flagged():
    findings = audit_files({"sshd_config": load("flawed-sshd_config"),
                            "s.sh": load("clean-startup.sh")})
    ids = {f.rule_id for f in findings}
    assert "SSHD_PERMITROOTLOGIN" in ids
    assert "SSHD_PASSWORD AUTHENTICATION" not in ids  # sanity: exact id below
    assert "SSHD_PASSWORDAUTHENTICATION" in ids
    assert "SSHD_PERMITEMPTYPASSWORDS" in ids


def test_clean_sshd_quiet():
    findings = audit_files({"sshd_config": load("clean-sshd_config"),
                            "s.sh": load("clean-startup.sh")})
    assert not any(f.rule_id.startswith("SSHD_") for f in findings)

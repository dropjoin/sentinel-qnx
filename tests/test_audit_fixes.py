"""Regression tests for the 2026-11-12 audit fixes.

Each group pins one proven bug: a canonical input the auditor used to
miss (or mis-flag), the repair, and the re-audit converging. The
pre-existing suites (test_rules, test_parser_explain, test_fix,
test_sshd, test_passwd_json) are untouched and must keep passing.
"""
from pathlib import Path

import pytest

from sentinel.buildfile import fixed_octal_mode, mode_grants_world_write, world_writable
from sentinel.cli import main
from sentinel.explain import IMPACT, narrative
from sentinel.fix import _fix_perms_value, fix_files, fix_text
from sentinel.rules import audit_files

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
APS = "sched_aps -c safety=30\n"


def load(name):
    return (SAMPLES / name).read_text()


def ids(files):
    return {f.rule_id for f in audit_files(files)}


# B1: canonical inetd.conf service lines, and tftpd.

def test_inetd_conf_service_lines_flagged():
    for line in ("telnet stream tcp nowait root /usr/sbin/telnetd telnetd",
                 "ftp stream tcp nowait root /usr/sbin/ftpd ftpd",
                 "tftp dgram udp wait root /usr/sbin/tftpd tftpd"):
        assert "CLEARTEXT_SERVICE" in ids({"inetd.conf": line + "\n",
                                           "s.sh": APS})


def test_inetd_line_naming_tftpd_flagged():
    assert "CLEARTEXT_SERVICE" in ids(
        {"x.sh": "inetd /etc/inetd.conf # tftpd enabled\n", "s.sh": APS})


def test_flawed_startup_still_flags_cleartext():
    assert "CLEARTEXT_SERVICE" in ids(
        {"s.sh": load("flawed-startup.sh"), "aps.sh": APS})


def test_ftp_prose_is_not_a_service():
    assert "CLEARTEXT_SERVICE" not in ids(
        {"notes.txt": "ftp is disabled on this image\n", "s.sh": APS})


# B2: chmod modes are evaluated, not enumerated.

@pytest.mark.parametrize("line", [
    "chmod 777 /data/x", "chmod 0777 /data/x", "chmod 7777 /data/x",
    "chmod 0666 /data/x", "chmod 666 /data/x", "chmod 7 /data/x",
    "chmod 77 /data/x", "chmod -R 777 /data/x", "chmod -v 777 /data/x",
    "chmod -- 777 /data/x", "chmod o+rwx /data/x", "chmod a+rwx /data/x",
    "chmod ugo+w /data/x", "chmod +w /data/x", "chmod o=rw /data/x",
    "chmod 777 /data/x; echo done",
])
def test_world_writable_chmod_flagged(line):
    assert "PERMISSIVE_MODE" in ids({"s.sh": line + "\n" + APS})


@pytest.mark.parametrize("line", [
    "chmod 755 /data/x", "chmod 0755 /data/x", "chmod 644 /data/x",
    "chmod 4755 /data/x", "chmod o-w /data/x", "chmod o=r /data/x",
    "chmod u=rwx,go=rx /data/x", "chmod +x /data/x",
])
def test_safe_chmod_not_flagged(line):
    assert "PERMISSIVE_MODE" not in ids({"s.sh": line + "\n" + APS})


@pytest.mark.parametrize("line,quiet", [
    ("umask 0", False), ("umask 000", False), ("umask 0000", False),
    ("umask 022", True), ("umask 027", True), ("umask 077", True),
])
def test_umask_modes(line, quiet):
    found = "PERMISSIVE_MODE" in ids({"s.sh": line + "\n" + APS})
    assert found == (not quiet)


def test_fix_chmod_mappings():
    assert "chmod 755 " in fix_text("s.sh", "chmod 777 /x\n")
    assert "chmod 644 " in fix_text("s.sh", "chmod 666 /x\n")
    assert "chmod 0755 " in fix_text("s.sh", "chmod 0777 /x\n")
    assert "chmod 0644 " in fix_text("s.sh", "chmod 0666 /x\n")
    assert "chmod 7755 " in fix_text("s.sh", "chmod 7777 /x\n")
    assert "chmod 755 " in fix_text("s.sh", "chmod a+rwx /x\n")
    assert "chmod -R 755 " in fix_text("s.sh", "chmod -R 777 /x\n")
    assert "chmod 755 /x\n" in fix_text("s.sh", "chmod 755 /x\n")
    fixed = fix_text("s.sh", "chmod 777 /x; echo done\n")
    assert fixed.startswith("chmod 755 /x; echo done")


def test_fix_chmod_converges_for_every_flagged_mode():
    for line in ("chmod 777 /x", "chmod 0777 /x", "chmod 7777 /x",
                 "chmod 0666 /x", "chmod o+rwx /x", "chmod -v 777 /x",
                 "chmod 7 /x", "umask 000"):
        fixed = fix_text("s.sh", line + "\n")
        assert "PERMISSIVE_MODE" not in ids({"s.sh": fixed, "a.sh": APS})


# B3: version lines with suffixes, tails, comments, short versions.

@pytest.mark.parametrize("line", [
    "openssl = 1.0.2k", "openssl = 1.0.2 # pinned",
    "openssl = 1.0", "openssl-1.0.2k", "openssl = 1.0.2k-1ubuntu1",
    "openssl = 1.1.0l", "busybox = 1.24.2",
])
def test_vulnerable_versions_flagged(line):
    assert "VULN_COMPONENT" in ids({"m.txt": line + "\n", "s.sh": APS})


@pytest.mark.parametrize("line", [
    "openssl = 3.0.13", "openssl = 1.1.1", "zlib = 1.2.11",
    "zlib = 1.3.1", "busybox = 1.36.1", "customdriver = 3.1.0",
])
def test_maintained_versions_not_flagged(line):
    assert "VULN_COMPONENT" not in ids({"m.txt": line + "\n", "s.sh": APS})


# B4: dispatch by sshd_config name; buildfiles case-insensitively.

def test_sshd_rules_ignore_unrelated_file_under_sshd_dir():
    assert not any(r.startswith("SSHD_") for r in ids(
        {"docs/sshd/notes.txt": "PermitRootLogin yes\n", "s.sh": APS}))


def test_sshd_config_dropin_still_audited():
    assert "SSHD_PERMITROOTLOGIN" in ids(
        {"etc/sshd_config.d/01.conf": "PermitRootLogin yes\n", "s.sh": APS})


def test_uppercase_build_extension_audited_and_fixed():
    assert "WORLD_WRITABLE_FILE" in ids(
        {"IMG.BUILD": load("flawed.build"), "s.sh": APS})
    fixed = fix_text("IMG.BUILD", load("flawed.build"))
    assert "perms=0777" not in fixed


# B5: comment-only APS mentions are not configuration.

def test_comment_only_aps_does_not_silence_check():
    assert "NO_ADAPTIVE_PARTITIONING" in ids(
        {"s.sh": "# TODO: add aps config someday\necho hi\n"})
    assert "NO_ADAPTIVE_PARTITIONING" in ids(
        {"s.sh": "echo hi # aps\n"})


def test_real_aps_line_silences_check():
    assert "NO_ADAPTIVE_PARTITIONING" not in ids({"s.sh": APS})


# B6: sshd first-obtained-value wins; Protocol lists.

def test_sshd_first_value_wins():
    assert "SSHD_PERMITROOTLOGIN" not in ids(
        {"sshd_config": "PermitRootLogin no\nPermitRootLogin yes\n",
         "s.sh": APS})
    found = audit_files(
        {"sshd_config": "PermitRootLogin yes\nPermitRootLogin no\n",
         "s.sh": APS})
    assert sum(1 for f in found if f.rule_id == "SSHD_PERMITROOTLOGIN") == 1


@pytest.mark.parametrize("line,flagged", [
    ("Protocol 1", True), ("Protocol 2,1", True), ("Protocol 1,2", True),
    ("Protocol 2, 1", True), ("Protocol 2", False),
])
def test_sshd_protocol_versions(line, flagged):
    found = "SSHD_PROTOCOL1" in ids({"sshd_config": line + "\n", "s.sh": APS})
    assert found == flagged


def test_sshd_protocol_first_value_wins():
    assert "SSHD_PROTOCOL1" not in ids(
        {"sshd_config": "Protocol 2\nProtocol 1\n", "s.sh": APS})


# B7: shadow is not passwd; dotted users; uid "00".

def test_shadow_lastchange_is_not_uid():
    found = ids({"shadow": "daemon:$6$salt$hash:0:0:99999:7:::\n", "s.sh": APS})
    assert "EXTRA_UID0" not in found


def test_shadow_empty_password_still_flagged():
    assert "EMPTY_PASSWORD" in ids(
        {"shadow": "daemon::18000:0:99999:7:::\n", "s.sh": APS})


def test_dotted_username_empty_password():
    assert "EMPTY_PASSWORD" in ids(
        {"passwd": "field.tech::1000:1000:F:/home/f:/bin/sh\n", "s.sh": APS})


@pytest.mark.parametrize("line,flagged", [
    ("evil:x:00:0:Evil:/:/bin/sh", True),
    ("evil:x:0:0:Evil:/:/bin/sh", True),
    ("evil:x:0001:0:Evil:/:/bin/sh", False),
    ("root:x:0:0:Superuser:/root:/bin/sh", False),
])
def test_uid_zero_forms(line, flagged):
    found = "EXTRA_UID0" in ids({"passwd": line + "\n", "s.sh": APS})
    assert found == flagged


def test_master_passwd_uid_check_applies():
    assert "EXTRA_UID0" in ids(
        {"master.passwd": "evil:x:0:0::0:0:Evil:/:/bin/sh\n", "s.sh": APS})


# B8/B9: mode evaluation and repair preserve special bits.

@pytest.mark.parametrize("mode,expected", [
    ("0777", True), ("777", True), ("077", True), ("7", True),
    ("7777", True), ("4777", True), ("o+w", True), ("a+w", True),
    ("a=rwx", True), ("a+rwx", True), ("o+rwx", True), ("ugo+w", True),
    ("o=rw", True), ("+w", True),
    ("0755", False), ("0644", False), ("4755", False), ("0", False),
    ("o-w", False), ("o=r", False), ("u=rwx", False), ("", False),
])
def test_mode_grants_world_write(mode, expected):
    assert mode_grants_world_write(mode) == expected
    assert world_writable(mode) == expected


@pytest.mark.parametrize("mode,fixed", [
    ("0777", "0755"), ("777", "755"), ("666", "644"), ("4777", "4755"),
    ("7777", "7755"), ("077", "055"), ("0755", "0755"), ("4755", "4755"),
])
def test_fixed_octal_mode(mode, fixed):
    assert fixed_octal_mode(mode) == fixed
    assert _fix_perms_value(mode) == fixed


def test_fix_buildfile_perms_keeps_special_bits():
    fixed = fix_text("img.build", "[perms=4777] bin/x = ./x\n")
    assert "perms=4755" in fixed
    assert "WORLD_WRITABLE_FILE" not in ids(
        {"img.build": fixed, "s.sh": APS})


# B10: fix output keeps same-basename inputs distinct and contained.

def test_fix_files_no_basename_collision(tmp_path):
    out = tmp_path / "out"
    written = fix_files({"a/x.sh": "chmod 777 /q\n",
                         "b/x.sh": "chmod 666 /q\n"}, str(out))
    assert len(written) == 2
    assert (out / "a" / "x.sh").read_text() == "chmod 755 /q\n"
    assert (out / "b" / "x.sh").read_text() == "chmod 644 /q\n"


def test_fix_files_cannot_escape_output_dir(tmp_path):
    out = tmp_path / "out"
    written = fix_files({"../../evil.sh": "echo hi\n"}, str(out))
    target = Path(next(iter(written)))
    assert out.resolve() in target.resolve().parents
    assert (out / "evil.sh").exists()


def test_fix_files_reaudit_still_dispatches_by_name(tmp_path):
    out = tmp_path / "out"
    written = fix_files({"img.build": load("flawed.build"),
                         "etc/sshd_config": load("flawed-sshd_config")},
                        str(out))
    after = ids(written)
    assert "WORLD_WRITABLE_FILE" not in after  # perms were fixed
    assert "SSHD_PERMITROOTLOGIN" in after  # sshd is a human decision


# B11: CLI input handling.

def test_cli_missing_path_is_clean_error(capsys):
    assert main(["audit", "/nonexistent-path-xyz-12345"]) == 2
    assert "error" in capsys.readouterr().err.lower()


def test_cli_empty_dir_is_error_not_clean(capsys, tmp_path):
    assert main(["audit", str(tmp_path)]) == 2
    assert "no files" in capsys.readouterr().err.lower()


def test_cli_same_file_twice_audited_once(capsys, tmp_path, monkeypatch):
    target = tmp_path / "x.sh"
    target.write_text(load("flawed-startup.sh"))
    monkeypatch.chdir(tmp_path)
    main(["audit", "x.sh", str(target)])
    out = capsys.readouterr().out
    assert out.count("DEBUG_SHELL") == 1


def test_cli_oversized_file_skipped_with_warning(capsys, tmp_path):
    big = tmp_path / "big.bin"
    with big.open("wb") as fh:
        fh.truncate(10 * 1024 * 1024 + 1)
    assert main(["audit", str(big)]) == 2
    assert "larger than" in capsys.readouterr().err


def test_cli_dir_walk_skips_oversized_but_audits_rest(capsys, tmp_path):
    (tmp_path / "x.sh").write_text(load("flawed-startup.sh"))
    with (tmp_path / "big.bin").open("wb") as fh:
        fh.truncate(10 * 1024 * 1024 + 1)
    assert main(["audit", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "larger than" in err


# B12: narrative covers every rule id; set-level location has no ":0".

def test_narrative_covers_every_rule_id():
    files = {f"samples/{p.name}": p.read_text() for p in SAMPLES.iterdir()
             if p.is_file()}
    files["proto/sshd_config"] = "Protocol 1\n"
    found = audit_files(files)
    # NO_ADAPTIVE_PARTITIONING is set-level and the clean sample
    # supplies APS, so it only appears in an APS-free set.
    found += audit_files({"noaps.sh": "echo hi\n"})
    missing = {f.rule_id for f in found} - set(IMPACT)
    assert not missing
    text = narrative(found)
    assert text.count("Impact scenario:") == len(found)
    assert "(image set):0" not in text


def test_narrative_names_set_level_finding_without_line_zero():
    text = narrative(audit_files({"s.sh": "echo hi\n"}))
    assert "(image set)" in text
    assert ":0" not in text

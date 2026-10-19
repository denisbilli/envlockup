from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import envlockup
from envlockup import EnvlockupError, NoKeyError, PassphraseRequiredError
from envlockup._dotenv import parse as dotenv_parse

VECTORS = json.loads((Path(__file__).parents[2] / "test" / "vectors.json").read_text(encoding="utf-8"))
SEALED = VECTORS["files"][0]
KEYS = VECTORS["keys"]


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    for name in ("ENVLOCKUP_PRIVATE_KEY", "ENVLOCKUP_IDENTITY", "ENVLOCKUP_SSH_PASSPHRASE", "ENVLOCKUP_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))  # no ~/.ssh/id_ed25519
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    path = tmp_path / ".env"
    path.write_text(SEALED["text"], encoding="utf-8")
    return path


def test_load_with_inline_key(env_file, monkeypatch):
    monkeypatch.setenv("ENVLOCKUP_PRIVATE_KEY", KEYS["age"]["private"])
    assert envlockup.load(env_file) == SEALED["expected"]


def test_inline_key_with_flattened_newlines(env_file, monkeypatch):
    monkeypatch.setenv("ENVLOCKUP_PRIVATE_KEY", KEYS["ssh"]["private"].strip().replace("\n", "\\n"))
    assert envlockup.load(env_file) == SEALED["expected"]


def test_identity_file_and_passphrase(env_file, tmp_path, monkeypatch):
    key = tmp_path / "key"
    key.write_text(KEYS["ssh_passphrase"]["private"])
    monkeypatch.setenv("ENVLOCKUP_IDENTITY", str(key))
    with pytest.raises(PassphraseRequiredError):
        envlockup.load(env_file)
    with pytest.raises(EnvlockupError, match="wrong passphrase"):
        envlockup.load(env_file, passphrase="nope")
    monkeypatch.setenv("ENVLOCKUP_SSH_PASSPHRASE", KEYS["ssh_passphrase"]["passphrase"])
    assert envlockup.load(env_file) == SEALED["expected"]


def test_default_ssh_key(env_file, tmp_path):
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "id_ed25519").write_text(KEYS["ssh"]["private"])
    assert envlockup.load(env_file) == SEALED["expected"]


def test_explicit_key_wins_over_default(env_file, tmp_path, monkeypatch):
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "id_ed25519").write_text(KEYS["ssh"]["private"])
    monkeypatch.setenv("ENVLOCKUP_PRIVATE_KEY", KEYS["outsider_age"]["private"])
    with pytest.raises(envlockup.NotARecipientError):
        envlockup.load(env_file)


def test_no_key(env_file):
    with pytest.raises(NoKeyError, match="ssh-agent is not supported"):
        envlockup.load(env_file)


def test_plain_file_needs_no_key(tmp_path, env_file):
    plain = tmp_path / "plain.env"
    plain.write_text("A=1\nB='two'\n")
    assert envlockup.load(plain) == {"A": "1", "B": "two"}


def test_config(env_file, monkeypatch):
    monkeypatch.setenv("ENVLOCKUP_PRIVATE_KEY", KEYS["age"]["private"])
    monkeypatch.setenv("ENVLOCKUP_SSH_PASSPHRASE", "unused")
    target = {"EMPTY": "already set"}
    parsed = envlockup.config(env_file, environ=target)
    assert parsed == SEALED["expected"]
    assert target["EMPTY"] == "already set"
    assert target["DATABASE_URL"] == SEALED["expected"]["DATABASE_URL"]
    assert "ENVLOCKUP_PRIVATE_KEY" not in os.environ
    assert "ENVLOCKUP_SSH_PASSPHRASE" not in os.environ

    monkeypatch.setenv("ENVLOCKUP_PRIVATE_KEY", KEYS["age"]["private"])
    envlockup.config(env_file, environ=target, override=True)
    assert target["EMPTY"] == ""


def test_config_default_path_and_missing_file(env_file, monkeypatch):
    monkeypatch.chdir(env_file.parent)
    monkeypatch.setenv("ENVLOCKUP_PRIVATE_KEY", KEYS["age"]["private"])
    assert envlockup.config(environ={}) == SEALED["expected"]
    assert envlockup.config("missing.env", environ={}) == {}


def cli(*args, env, cwd):
    return subprocess.run(
        [sys.executable, "-m", "envlockup", *args], env=env, cwd=cwd, capture_output=True, text=True, encoding="utf-8"
    )


@pytest.fixture
def cli_env(env_file):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ENVLOCKUP_")}
    env["ENVLOCKUP_PRIVATE_KEY"] = KEYS["age"]["private"]
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def test_cli_get_and_decrypt(env_file, cli_env):
    r = cli("get", "UNICODE", env=cli_env, cwd=env_file.parent)
    assert (r.returncode, r.stdout) == (0, SEALED["expected"]["UNICODE"] + "\n")
    r = cli("get", "NOPE", env=cli_env, cwd=env_file.parent)
    assert r.returncode == 1 and "not set" in r.stderr
    r = cli("-f", str(env_file), "decrypt", env=cli_env, cwd=env_file.parent)
    assert r.returncode == 0, r.stderr
    assert dotenv_parse(r.stdout) == SEALED["expected"]
    r = cli("-f", str(env_file), "decrypt", "--format", "json", env=cli_env, cwd=env_file.parent)
    assert json.loads(r.stdout) == SEALED["expected"]


def test_cli_run(env_file, cli_env):
    script = (
        "import json, os; "
        "print(json.dumps({k: os.environ.get(k) for k in ['MULTILINE', 'EMPTY', 'ENVLOCKUP_PRIVATE_KEY']}))"
    )
    cli_env["EMPTY"] = "from parent"
    r = cli("run", "--", sys.executable, "-c", script, env=cli_env, cwd=env_file.parent)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {
        "MULTILINE": SEALED["expected"]["MULTILINE"],
        "EMPTY": "from parent",
        "ENVLOCKUP_PRIVATE_KEY": None,
    }
    r = cli("run", "--override", "--", sys.executable, "-c", script, env=cli_env, cwd=env_file.parent)
    assert json.loads(r.stdout)["EMPTY"] == ""


def test_cli_run_exit_code_and_missing_command(env_file, cli_env):
    r = cli("run", "--", sys.executable, "-c", "raise SystemExit(7)", env=cli_env, cwd=env_file.parent)
    assert r.returncode == 7
    r = cli("run", "--", "envlockup-no-such-command", env=cli_env, cwd=env_file.parent)
    assert r.returncode == 127


def test_cli_error(env_file, cli_env):
    cli_env["ENVLOCKUP_PRIVATE_KEY"] = KEYS["outsider_age"]["private"]
    r = cli("get", "UNICODE", env=cli_env, cwd=env_file.parent)
    assert r.returncode == 1 and "not encrypted for your key" in r.stderr

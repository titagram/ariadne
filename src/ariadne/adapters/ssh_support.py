"""Shared secret-safe OpenSSH ProcessSpec construction."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from ariadne.adapters.base import AdapterContext, AdapterError, ProcessSpec

_USERNAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")


def validated_ssh_inputs(
    inputs: dict[str, object],
    context: AdapterContext,
) -> tuple[str, Path, int]:
    if context.run_root is None:
        raise AdapterError("SSH credential use requires a durable run root")
    username = inputs.get("username")
    if not isinstance(username, str) or _USERNAME.fullmatch(username) is None:
        raise AdapterError("username is not a valid bounded SSH account name")
    credential_ref = inputs.get("credential_ref")
    if not isinstance(credential_ref, str) or not credential_ref:
        raise AdapterError("credential_ref must name a protected run credential")
    run_root = context.run_root.resolve()
    secret_root = (run_root / "secrets").resolve()
    secret = (run_root / credential_ref).resolve()
    try:
        secret.relative_to(secret_root)
    except ValueError as exc:
        raise AdapterError("credential_ref is outside the protected credential store") from exc
    if not secret.is_file() or secret.stat().st_mode & 0o077:
        raise AdapterError("credential_ref is missing or has unsafe permissions")
    port = inputs.get("port", 22)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise AdapterError("SSH port must be an integer between 1 and 65535")
    return username, secret, port


def prepare_askpass(run_root: Path) -> Path:
    source = Path(__file__).resolve().parents[1] / "runtime" / "ssh_askpass.py"
    workspace = run_root.resolve() / "workspace"
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = workspace / "ariadne_ssh_askpass.py"
    content = source.read_bytes()
    expected = hashlib.sha256(content).hexdigest()
    if (
        not destination.is_file()
        or hashlib.sha256(destination.read_bytes()).hexdigest() != expected
    ):
        temporary = workspace / f".{destination.name}.{os.getpid()}.tmp"
        temporary.write_bytes(content)
        temporary.chmod(0o700)
        os.replace(temporary, destination)
    destination.chmod(0o700)
    return destination


def ssh_process_spec(
    *,
    inputs: dict[str, object],
    context: AdapterContext,
    remote_command: str,
    timeout_seconds: int = 30,
    max_output_bytes: int = 256 * 1024,
) -> ProcessSpec:
    username, secret, port = validated_ssh_inputs(inputs, context)
    assert context.run_root is not None
    helper = prepare_askpass(context.run_root)
    known_hosts = context.run_root.resolve() / "workspace" / "known_hosts"
    return ProcessSpec(
        argv=(
            "ssh",
            "-o",
            "BatchMode=no",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            "ConnectTimeout=10",
            "-p",
            str(port),
            "--",
            f"{username}@{context.target.host}",
            remote_command,
        ),
        cwd=context.run_root.resolve() / "workspace",
        environment={
            "ARIADNE_SECRET_FILE": str(secret),
            "DISPLAY": "ariadne:0",
            "SSH_ASKPASS": str(helper),
            "SSH_ASKPASS_REQUIRE": "force",
        },
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )

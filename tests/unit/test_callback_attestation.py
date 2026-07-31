"""Focused tests for local reverse-callback address attestation."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from ariadne.runtime.platform import detect_host
from ariadne.runtime.preflight import (
    CallbackAttestationError,
    attest_callback_address,
)


def _runner(
    outputs: dict[tuple[str, ...], tuple[int, str, str]]
) -> Callable[..., tuple[int, str, str]]:
    def run(argv: tuple[str, ...], *, timeout_seconds: float) -> tuple[int, str, str]:
        assert timeout_seconds <= 3
        return outputs[argv]

    return run


@pytest.mark.parametrize(
    ("host", "outputs", "expected_source"),
    [
        (
            detect_host("Darwin", "arm64"),
            {
                ("route", "-n", "get", "10.129.1.20"): (
                    0,
                    "   route to: 10.129.1.20\ninterface: utun7\n",
                    "",
                ),
                ("ifconfig", "utun7"): (0, "inet 10.10.14.8 --> 10.10.14.8\n", ""),
            },
            "macos:route-get+ifconfig",
        ),
        (
            detect_host("Linux", "x86_64"),
            {
                ("ip", "-4", "route", "get", "10.129.1.20"): (
                    0,
                    "10.129.1.20 via 10.10.14.1 dev tun0 src 10.10.14.8 uid 501\n",
                    "",
                ),
                ("ip", "-4", "addr", "show", "dev", "tun0"): (
                    0,
                    "7: tun0: <POINTOPOINT,UP>\n    inet 10.10.14.8/23 scope global tun0\n",
                    "",
                ),
            },
            "linux:ip-route-get+ip-addr",
        ),
    ],
)
def test_callback_address_is_attested_from_local_route_and_owned_interface(
    host, outputs: dict[tuple[str, ...], tuple[int, str, str]], expected_source: str
) -> None:
    attestation = attest_callback_address(
        advertised_address="10.10.14.8",
        target="10.129.1.20",
        host=host,
        command_runner=_runner(outputs),
    )

    assert attestation.source == expected_source
    assert attestation.interface in {"utun7", "tun0"}
    assert attestation.as_plan_data() == {
        "address": "10.10.14.8",
        "target": "10.129.1.20",
        "source": expected_source,
        "interface": attestation.interface,
        "route_sha256": attestation.route_sha256,
        "ownership_sha256": attestation.ownership_sha256,
    }


def test_callback_address_rejects_unowned_or_bridge_interface_before_runtime() -> None:
    host = detect_host("Linux", "x86_64")
    outputs = {
        ("ip", "-4", "route", "get", "10.129.1.20"): (
            0,
            "10.129.1.20 dev docker0 src 172.29.0.2\n",
            "",
        ),
    }

    with pytest.raises(CallbackAttestationError, match="bridge|container|unattested"):
        attest_callback_address(
            advertised_address="172.29.0.2",
            target="10.129.1.20",
            host=host,
            command_runner=_runner(outputs),
        )

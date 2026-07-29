"""Contract tests for the pinned Kali, ZAP, and netguard container stack.

Verifies the structural invariants of the Compose orchestrator, the
Kali Dockerfile, the netguard egress entrypoint, and pinned image/manifest
records — all without a running Docker daemon.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from ariadne.execution.contracts import ExecutionContractRegistry

_CONTAINERS = Path(__file__).resolve().parent.parent.parent / "containers"


# ── Compose topology ────────────────────────────────────────────────────────────


def test_compose_shares_netguard_namespace() -> None:
    """Kali and ZAP must route egress through netguard's NET_ADMIN namespace."""
    compose = yaml.safe_load((_CONTAINERS / "compose.yaml").read_text())
    services = compose["services"]

    assert services["kali"]["network_mode"] == "service:netguard"
    assert services["zap"]["network_mode"] == "service:netguard"
    assert services["netguard"]["cap_add"] == ["NET_ADMIN"]

    # Only netguard carries NET_ADMIN; Kali and ZAP must not widen their caps.
    assert "NET_ADMIN" not in services["kali"].get("cap_add", [])


def test_netguard_image_includes_nftables() -> None:
    """Netguard must build an image with the nft executable it invokes."""
    compose = yaml.safe_load((_CONTAINERS / "compose.yaml").read_text())
    build = compose["services"]["netguard"]["build"]
    assert build["context"] == "."
    assert build["dockerfile"] == "netguard/Dockerfile"

    dockerfile = (_CONTAINERS / "netguard" / "Dockerfile").read_text()
    assert "nftables" in dockerfile


def test_compose_has_required_services() -> None:
    """Stack must expose kali, zap, and netguard services."""
    compose = yaml.safe_load((_CONTAINERS / "compose.yaml").read_text())
    service_names = set(compose["services"])
    assert service_names >= {"kali", "zap", "netguard"}


def test_kali_root_filesystem_is_read_only_with_persistent_home() -> None:
    """Pinned tools/templates stay immutable while tool state uses workspace."""
    compose = yaml.safe_load((_CONTAINERS / "compose.yaml").read_text())
    kali = compose["services"]["kali"]

    assert kali["read_only"] is True
    assert any(str(value).startswith("/tmp:") for value in kali["tmpfs"])
    assert "HOME=/workspace/home" in kali["environment"]


# ── Image lock invariants ───────────────────────────────────────────────────────


def test_image_lock_records_pinned_digests() -> None:
    """Every container image must be pinned by digest in image-lock.yaml."""
    lock = yaml.safe_load((_CONTAINERS / "image-lock.yaml").read_text())
    assert isinstance(lock, dict)
    records = lock.get("images", [])
    assert len(records) >= 2  # kali-rolling + stable ZAP

    for rec in records:
        assert "image" in rec, f"Missing 'image' key in {rec}"
        assert "digest" in rec, f"Missing pinned digest in {rec}"
        assert rec["digest"].startswith("sha256:"), (
            f"Digest must be sha256: in {rec['image']}"
        )
        assert "platform" in rec
        assert "retrieved_at" in rec


def test_image_lock_kali_and_zap_present() -> None:
    """image-lock must reference both kalilinux and ZAP images."""
    lock = yaml.safe_load((_CONTAINERS / "image-lock.yaml").read_text())
    images = {rec["image"] for rec in lock.get("images", [])}
    assert any("kalilinux" in img for img in images), "Missing kalilinux image"
    assert any("zap" in img.lower() for img in images), "Missing ZAP image"


# ── Tool manifest ───────────────────────────────────────────────────────────────


def test_tool_manifest_exists_and_is_valid() -> None:
    """tool-manifest.yaml must be parseable YAML with a 'packages' list."""
    manifest = yaml.safe_load((_CONTAINERS / "tool-manifest.yaml").read_text())
    assert isinstance(manifest, dict)
    pkgs = manifest.get("packages", [])
    assert isinstance(pkgs, list)
    assert len(pkgs) > 0, "At least one tool package must be declared"


def test_tool_manifest_uses_kali_package_owners_for_curated_executables() -> None:
    """APT package names must match the owners exposed by Kali rolling."""
    manifest = yaml.safe_load((_CONTAINERS / "tool-manifest.yaml").read_text())
    packages = set(manifest["packages"])
    executables = set(manifest["executables"])

    assert {"exploitdb", "certipy-ad"} <= packages
    assert not {"searchsploit", "certipy"} & packages
    assert {"searchsploit", "certipy-ad"} <= executables
    assert "certipy" not in executables


def test_tool_manifest_is_curated_for_ariadne_runtime() -> None:
    """The image must install workflow tools without bulk or GUI metapackages."""
    manifest = yaml.safe_load((_CONTAINERS / "tool-manifest.yaml").read_text())
    packages = set(manifest["packages"])
    executables = set(manifest["executables"])

    assert not packages & {
        "kali-linux-headless",
        "kali-linux-default",
        "kali-linux-everything",
        "bloodhound",
        "wireshark",
        "hashcat",
    }
    assert {
        "chromium",
        "exploitdb",
        "httpx-toolkit",
        "metasploit-framework",
        "nmap",
        "nuclei",
        "tshark",
    } <= packages
    assert {
        "chromium",
        "httpx-toolkit",
        "msfconsole",
        "nmap",
        "nuclei",
        "searchsploit",
    } <= executables


def test_kali_backed_execution_contracts_are_present_in_the_curated_image() -> None:
    """A reachable specialist contract must not select an absent Kali tool."""
    manifest = yaml.safe_load((_CONTAINERS / "tool-manifest.yaml").read_text())
    executables = set(manifest["executables"])
    kali_backed_adapters = {
        "active_directory",
        "httpx",
        "metasploit",
        "nmap",
        "nuclei",
        "pivot",
        "postex",
        "research",
        "screenshot",
    }
    required = {
        executable
        for contract in ExecutionContractRegistry.curated().contracts.values()
        if contract.adapter in kali_backed_adapters
        for executable in contract.executable_ids
    }

    assert required <= executables, (
        f"Curated Kali image is missing contract executables: {sorted(required - executables)}"
    )


# ── Kali Dockerfile ─────────────────────────────────────────────────────────────


def test_kali_dockerfile_uses_pinned_base_image() -> None:
    """Dockerfile declares ARG for pinned digest, reads tool manifest,
    and creates unprivileged user."""
    dockerfile = (_CONTAINERS / "kali" / "Dockerfile").read_text()
    assert "ARG KALI_BASE_REF" in dockerfile, (
        "Must declare ARG KALI_BASE_REF for pinned image"
    )
    assert "tool-manifest.yaml" in dockerfile, (
        "Must read packages from tool-manifest.yaml"
    )
    assert "ariadne" in dockerfile, (
        "Must create an unprivileged ariadne user"
    )

def test_kali_dockerfile_clears_apt_lists() -> None:
    """Dockerfile must clear APT lists to keep the image lean."""
    dockerfile = (_CONTAINERS / "kali" / "Dockerfile").read_text()
    assert any(
        keyword in dockerfile
        for keyword in ("rm -rf /var/lib/apt/lists", "apt-get clean")
    ), "Must clear APT lists"


def test_kali_dockerfile_redeclares_runtime_build_args_after_from() -> None:
    """Build args used by RUN must be visible inside the image stage."""
    dockerfile = (_CONTAINERS / "kali" / "Dockerfile").read_text()
    stage = dockerfile.split("FROM ", maxsplit=1)[1]

    assert "ARG NUCLEI_TEMPLATES_REF" in stage


# ── Netguard entrypoint ─────────────────────────────────────────────────────────


def test_netguard_entrypoint_drops_default_egress() -> None:
    """Netguard's entrypoint must end with a default-drop rule."""
    entrypoint = (_CONTAINERS / "netguard" / "entrypoint.sh").read_text()
    assert any(
        policy in entrypoint for policy in ("policy drop", "drop")
    ), "Must drop default egress"


def test_netguard_logs_denied_egress_without_accepting_it() -> None:
    """The catch-all output rule must log and drop, never bypass default deny."""
    entrypoint = (_CONTAINERS / "netguard" / "entrypoint.sh").read_text()
    assert 'output log prefix \\"ARIADNE-DENY-OUT: \\" group 0 drop' in entrypoint
    assert 'output log prefix "ARIADNE-DENY-OUT: " group 0 accept' not in entrypoint


def test_netguard_rate_limit_applies_only_to_allowlisted_target_traffic() -> None:
    """SYN limiting must not accept destinations outside the target allowlist."""
    entrypoint = (_CONTAINERS / "netguard" / "entrypoint.sh").read_text()
    assert 'tcp dport "$port" tcp flags syn limit rate over 100/second drop' in entrypoint
    assert 'tcp flags syn limit rate 100/second accept' not in entrypoint


def test_netguard_entrypoint_allows_established_and_loopback() -> None:
    """Entrypoint must allow established connections and loopback before drop."""
    entrypoint = (_CONTAINERS / "netguard" / "entrypoint.sh").read_text()
    assert "established" in entrypoint, "Must allow established traffic"
    assert any(
        term in entrypoint for term in ("lo", "loopback", "127.0.0.0/8")
    ), "Must allow loopback"


def test_netguard_entrypoint_allows_docker_dns() -> None:
    """Entrypoint must allow Docker DNS resolution before restricting egress."""
    entrypoint = (_CONTAINERS / "netguard" / "entrypoint.sh").read_text()
    assert "53" in entrypoint or "dns" in entrypoint.lower(), (
        "Must allow Docker DNS on port 53"
    )

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ariadne.knowledge import (
    KnowledgeError,
    KnowledgeIndex,
    LocalToolProbe,
    RuntimeVerificationStore,
    ToolCardVerifier,
    ToolDiscovery,
    ToolVerificationBlockedError,
)

_LOCAL_PROBE_TEST_TIMEOUT_SECONDS = 3


def _write_node(root: Path, name: str, frontmatter: str, body: str = "Concise guidance.") -> None:
    path = root / f"{name}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\n{frontmatter.strip()}\n---\n\n{body}\n", encoding="utf-8")


def _knowledge_tree(root: Path, executable: str) -> KnowledgeIndex:
    _write_node(
        root,
        "sources/nmap",
        """
schema_version: 1
id: source.nmap.official
kind: source
title: Nmap official documentation
next: []
requires: []
policy: []
provenance: []
url: https://nmap.org/book/man.html
""",
    )
    _write_node(
        root,
        "methodology/discovery",
        """
schema_version: 1
id: methodology.discovery
kind: methodology
title: Bounded discovery
next: [service.tcp]
requires: []
policy: []
provenance: [source.nmap.official]
""",
    )
    _write_node(
        root,
        "services/tcp",
        """
schema_version: 1
id: service.tcp
kind: service
title: TCP service
next: [technique.tcp.port-scan]
requires: [methodology.discovery]
policy: []
provenance: [source.nmap.official]
""",
    )
    _write_node(
        root,
        "techniques/port-scan",
        """
schema_version: 1
id: technique.tcp.port-scan
kind: technique
title: TCP port scan
next: [tool.nmap]
requires: [service.tcp]
policy: [network.active_scan]
provenance: [source.nmap.official]
""",
    )
    _write_node(
        root,
        "tools/nmap",
        f"""
schema_version: 1
id: tool.nmap
kind: tool
title: Nmap
next: []
requires: [technique.tcp.port-scan]
policy: [network.active_scan]
provenance: [source.nmap.official]
status: curated
version: runtime
source_date: "2026-07-29"
documentation_source: official
tool:
  executable: {executable}
  version_args: [--version]
  help_args: [--help]
  official_source: source.nmap.official
""",
    )
    return KnowledgeIndex.load(root)


def _write_probe_tool(path: Path, *, marker: Path | None = None, help_ok: bool = True) -> None:
    marker_command = f"printf called > {marker!s}\n" if marker is not None else ""
    help_branch = (
        'printf "usage: bounded-probe [options]\\n"\nexit 0\n'
        if help_ok
        else 'printf "help unavailable\\n" >&2\nexit 2\n'
    )
    path.write_text(
        "#!/bin/sh\n"
        f"{marker_command}"
        'if [ "$1" = "--version" ]; then\n'
        '  printf "bounded-probe 1.2.3\\n"\n'
        "  exit 0\n"
        "fi\n"
        'if [ "$1" = "--help" ]; then\n'
        f"  {help_branch}"
        "fi\n"
        "exit 3\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_loader_validates_all_node_kinds_and_writes_a_stable_index(tmp_path: Path) -> None:
    tool = tmp_path / "bounded-probe"
    _write_probe_tool(tool)
    index = _knowledge_tree(tmp_path / "knowledge", str(tool))

    assert {node.kind.value for node in index.nodes.values()} == {
        "methodology",
        "service",
        "technique",
        "tool",
        "source",
    }
    assert index.node("tool.nmap").requires == ("technique.tcp.port-scan",)

    output = tmp_path / "knowledge-index.json"
    index.write(output)
    persisted = json.loads(output.read_text(encoding="utf-8"))

    assert persisted["schema_version"] == 1
    assert persisted["digest"] == index.digest
    assert [node["id"] for node in persisted["nodes"]] == sorted(index.nodes)
    assert KnowledgeIndex.load(tmp_path / "knowledge").digest == index.digest


def test_loader_rejects_a_dangling_graph_reference(tmp_path: Path) -> None:
    _write_node(
        tmp_path,
        "broken",
        """
schema_version: 1
id: methodology.broken
kind: methodology
title: Broken methodology
next: [service.missing]
requires: []
policy: []
provenance: []
""",
    )

    with pytest.raises(KnowledgeError, match="service.missing"):
        KnowledgeIndex.load(tmp_path)


def test_loader_rejects_non_https_official_sources(tmp_path: Path) -> None:
    _write_node(
        tmp_path,
        "source",
        """
schema_version: 1
id: source.insecure
kind: source
title: Insecure source
next: []
requires: []
policy: []
provenance: []
url: http://example.test/manual
""",
    )

    with pytest.raises(KnowledgeError, match="HTTPS"):
        KnowledgeIndex.load(tmp_path)


def test_repository_examples_form_a_valid_canonical_chain() -> None:
    root = Path(__file__).resolve().parents[2] / "knowledge"

    index = KnowledgeIndex.load(root)

    assert set(index.nodes) == {
        "methodology.lab.discovery",
        "service.http",
        "source.nmap.official",
        "source.openssh.official",
        "technique.tcp.port-scan",
        "tool.nmap",
        "tool.ssh",
    }
    assert index.node("technique.tcp.port-scan").next == ("tool.nmap",)


def test_runtime_verification_promotes_only_after_local_version_and_help(
    tmp_path: Path,
) -> None:
    tool = tmp_path / "bounded-probe"
    _write_probe_tool(tool)
    index = _knowledge_tree(tmp_path / "knowledge", str(tool))
    store = RuntimeVerificationStore(tmp_path / "runtime")
    verifier = ToolCardVerifier(
        index=index,
        probe=LocalToolProbe(
            timeout_seconds=_LOCAL_PROBE_TEST_TIMEOUT_SECONDS,
            max_output_bytes=256,
        ),
        store=store,
    )

    record = verifier.verify(
        "tool.nmap",
        allowed_policy=frozenset({"network.active_scan"}),
    )

    assert record.status == "runtime_verified"
    assert record.version == "bounded-probe 1.2.3"
    assert record.guidance == "usage: bounded-probe [options]"
    assert record.guidance_source == "local_help"
    assert store.get("tool.nmap") == record
    assert index.node("tool.nmap").status == "runtime_verified"
    assert index.node("tool.nmap").version == "bounded-probe 1.2.3"


def test_documentation_probe_does_not_promote_before_success(tmp_path: Path) -> None:
    tool = tmp_path / "bounded-probe"
    _write_probe_tool(tool)
    index = _knowledge_tree(tmp_path / "knowledge", str(tool))
    store = RuntimeVerificationStore(tmp_path / "runtime")
    verifier = ToolCardVerifier(
        index=index,
        probe=LocalToolProbe(
            timeout_seconds=_LOCAL_PROBE_TEST_TIMEOUT_SECONDS,
            max_output_bytes=256,
        ),
        store=store,
    )

    documented = verifier.inspect(
        "tool.nmap",
        allowed_policy=frozenset({"network.active_scan"}),
    )

    assert documented.status == "documented"
    assert index.node("tool.nmap").status == "curated"
    assert store.get("tool.nmap") is None


def test_unknown_tool_gets_a_concise_card_before_runtime_promotion(
    tmp_path: Path,
) -> None:
    tool = tmp_path / "bounded-probe"
    _write_probe_tool(tool)
    index = _knowledge_tree(tmp_path / "knowledge", str(tool))
    verifier = ToolCardVerifier(
        index=index,
        probe=LocalToolProbe(
            timeout_seconds=_LOCAL_PROBE_TEST_TIMEOUT_SECONDS,
            max_output_bytes=256,
        ),
        store=RuntimeVerificationStore(tmp_path / "runtime"),
    )
    discovery = ToolDiscovery(
        tool_id="tool.bounded-probe",
        title="Bounded Probe",
        executable=str(tool),
        policy=("network.active_scan",),
        requires=("methodology.discovery",),
        official_source_id="source.bounded-probe.official",
        official_source_url="https://example.test/bounded-probe",
        source_date="2026-07-29",
        summary="Concise capability and guardrail notes.",
    )

    documented = verifier.inspect_or_discover(
        discovery,
        allowed_policy=frozenset({"network.active_scan"}),
    )

    card_path = tmp_path / "knowledge" / "tools" / "bounded-probe.md"
    assert documented.status == "documented"
    assert index.node(discovery.tool_id).status == "discovered"
    assert "Concise capability" in card_path.read_text()
    assert "usage: bounded-probe" not in card_path.read_text()

    verifier.promote_after_success(documented)
    assert index.node(discovery.tool_id).status == "runtime_verified"


def test_policy_block_prevents_probe_and_runtime_promotion(tmp_path: Path) -> None:
    marker = tmp_path / "called"
    tool = tmp_path / "bounded-probe"
    _write_probe_tool(tool, marker=marker)
    index = _knowledge_tree(tmp_path / "knowledge", str(tool))
    store = RuntimeVerificationStore(tmp_path / "runtime")
    verifier = ToolCardVerifier(
        index=index,
        probe=LocalToolProbe(
            timeout_seconds=_LOCAL_PROBE_TEST_TIMEOUT_SECONDS,
            max_output_bytes=256,
        ),
        store=store,
    )

    with pytest.raises(ToolVerificationBlockedError, match="network.active_scan"):
        verifier.verify("tool.nmap", allowed_policy=frozenset())

    assert not marker.exists()
    assert store.get("tool.nmap") is None


def test_official_provider_is_a_bounded_fallback_for_missing_local_guidance(
    tmp_path: Path,
) -> None:
    tool = tmp_path / "bounded-probe-no-man-page"
    _write_probe_tool(tool, help_ok=False)
    index = _knowledge_tree(tmp_path / "knowledge", str(tool))
    store = RuntimeVerificationStore(tmp_path / "runtime")

    def official_provider(source_url: str, max_output_bytes: int) -> str:
        assert source_url == "https://nmap.org/book/man.html"
        return "official concise guidance " * 100

    verifier = ToolCardVerifier(
        index=index,
        probe=LocalToolProbe(
            timeout_seconds=_LOCAL_PROBE_TEST_TIMEOUT_SECONDS,
            max_output_bytes=64,
            man_executable=None,
        ),
        store=store,
        official_provider=official_provider,
    )

    record = verifier.verify(
        "tool.nmap",
        allowed_policy=frozenset({"network.active_scan"}),
    )

    assert record.status == "runtime_verified"
    assert record.guidance_source == "official_provider"
    assert len(record.guidance.encode("utf-8")) <= 64


def test_local_guidance_process_is_stopped_at_the_output_bound(tmp_path: Path) -> None:
    tool = tmp_path / "verbose-probe"
    tool.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then\n'
        '  printf "verbose-probe 1.0\\n"\n'
        "  exit 0\n"
        "fi\n"
        'if [ "$1" = "--help" ]; then\n'
        '  exec yes "0123456789"\n'
        "fi\n"
        "exit 3\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    index = _knowledge_tree(tmp_path / "knowledge", str(tool))
    verifier = ToolCardVerifier(
        index=index,
        probe=LocalToolProbe(
            timeout_seconds=_LOCAL_PROBE_TEST_TIMEOUT_SECONDS,
            max_output_bytes=64,
            man_executable=None,
        ),
        store=RuntimeVerificationStore(tmp_path / "runtime"),
    )

    record = verifier.verify(
        "tool.nmap",
        allowed_policy=frozenset({"network.active_scan"}),
    )

    assert len(record.guidance.encode("utf-8")) <= 64

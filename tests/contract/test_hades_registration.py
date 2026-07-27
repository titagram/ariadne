"""Contract tests for Hades plugin registration.

These tests use a RecordingPluginContext faking the Hades 0.17
PluginContext API to verify that register() exposes all expected
skills, tools, commands, and hooks.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ariadne.composition import register


@dataclass
class RecordingPluginContext:
    """Fake Hades PluginContext that records registration calls."""

    profile_name: str = "test"
    skills: list[tuple[str, str]] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    hooks: list[str] = field(default_factory=list)

    def register_skill(self, name: str, path: str, description: str) -> None:
        self.skills.append((name, str(path)))

    def register_tool(
        self,
        name: str,
        toolset: str,
        schema: dict,
        handler: object,
        is_async: bool = False,
        description: str = "",
        emoji: str = "",
        **kwargs: object,
    ) -> None:
        self.tools.append(name)

    def register_command(
        self,
        name: str,
        handler: object,
        description: str = "",
        args_hint: str = "",
        **kwargs: object,
    ) -> None:
        self.commands.append(name)

    def register_hook(self, name: str, callback: object, **kwargs: object) -> None:
        self.hooks.append(name)


def test_register_exposes_namespaced_skill_tools_command_and_hook() -> None:
    """register() exposes the skill, six tools, /ariadne cmd, and guard hook."""
    ctx = RecordingPluginContext(profile_name="test")
    register(ctx)
    assert ctx.skills == [("lab-pentest", "skills/lab-pentest/SKILL.md")]
    assert set(ctx.tools) == {
        "ariadne_prepare_engagement",
        "ariadne_bind_engagement",
        "ariadne_status",
        "ariadne_propose_plan",
        "ariadne_execute_plan",
        "ariadne_render_report",
    }
    assert "ariadne" in ctx.commands
    assert "pre_tool_call" in ctx.hooks

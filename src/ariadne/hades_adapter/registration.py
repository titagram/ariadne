from pathlib import Path
from typing import Any


def register_plugin(ctx: Any, services: object) -> None:
    """Register the Ariadne lab-pentest skill and bootstrap the plugin.

    Services are provided by composition.build_services and consumed
    by later tasks that wire tools, hooks, and commands through ctx.
    """
    skill_path = Path(__file__).parents[3] / "skills" / "lab-pentest" / "SKILL.md"
    ctx.register_skill(
        name="lab-pentest",
        path=skill_path,
        description="Controlled authorized lab and CTF pentesting",
    )

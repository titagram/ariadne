from pathlib import Path

import yaml


def test_plugin_manifest_and_skill_are_hades_loadable() -> None:
    root = Path(__file__).parents[2]
    manifest = yaml.safe_load((root / "plugin.yaml").read_text())
    assert manifest["name"] == "ariadne"
    assert manifest["kind"] == "standalone"
    assert manifest["manifest_version"] == 1
    assert (root / "__init__.py").is_file()
    assert (root / "skills/lab-pentest/SKILL.md").is_file()

"""The frozen engine's extraction path has no sibling development checkout."""
import tempfile
from pathlib import Path

from redjohn_core import skill_registry


def test_shallow_installed_skill_library_skips_development_path(monkeypatch):
    monkeypatch.delenv("REDJOHN_SKILLS_ROOT", raising=False)
    with tempfile.TemporaryDirectory(prefix="redjohn-packaged-skills-", dir="/tmp") as directory:
        package = Path(directory) / "redjohn_core"
        library = package / "skill_library" / "scan-low"
        library.mkdir(parents=True)
        (library / "SKILL.md").write_text(
            "---\nname: scan-low\ndescription: A packaged profile.\n---\n# Low\n"
        )
        monkeypatch.setattr(skill_registry, "__file__", str(package / "skill_registry.py"))
        registry = skill_registry.SkillRegistry()
        assert registry.get("scan-low").description == "A packaged profile."
        assert registry.root == library.parent.resolve()

"""Operator-authored local skill catalog, also bundled in the engine wheel."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from .errors import RJError
from .models import SkillRef

if TYPE_CHECKING:
    from .db import Store

MASTER_SKILL = "00-master-pentest-methodology"
SCAN_PROFILE_SKILLS = {mode: f"scan-{mode}" for mode in ("low", "standard", "high", "deep")}


@dataclass(frozen=True)
class LocalSkill:
    name: str
    description: str
    directory: Path
    content: str

    @property
    def skill_id(self) -> str:
        return "skl_" + hashlib.sha256(f"redjohn-local:{self.name}".encode()).hexdigest()[:24]

    def reference(self) -> SkillRef:
        return SkillRef(
            skill_id=self.skill_id,
            name=self.name,
            version="1",
            description=self.description,
            source="redjohn-local",
            content_hash=hashlib.sha256(self.content.encode()).hexdigest(),
        )


@lru_cache(maxsize=4)
def _load_skills_for_root(
    root_str: str, signature: tuple[tuple[str, int], ...]
) -> dict[str, LocalSkill]:
    del signature
    root = Path(root_str)
    skills: dict[str, LocalSkill] = {}
    for path in sorted(root.glob("*/SKILL.md")):
        content = path.read_text(encoding="utf-8")
        fields: dict[str, str] = {}
        if content.startswith("---\n"):
            for line in content.split("---", 2)[1].splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    fields[key.strip()] = value.strip()
        name = fields.get("name", "")
        if name != path.parent.name or not fields.get("description"):
            raise RJError("skill_catalog_invalid", f"Invalid skill frontmatter: {path.name}", status=503)
        skills[name] = LocalSkill(name, fields["description"], path.parent, content)
    return skills


class SkillRegistry:
    def __init__(self, root: Path | None = None) -> None:
        if root is None:
            override = os.environ.get("REDJOHN_SKILLS_ROOT")
            packaged = Path(__file__).with_name("skill_library")
            if override:
                root = Path(override)
            elif packaged.is_dir():
                root = packaged
            else:
                root = next(
                    (
                        candidate
                        for parent in Path(__file__).resolve().parents
                        for candidate in (parent / "skills", parent / "rj-desktop" / "skills")
                        if candidate.is_dir()
                    ),
                    packaged,
                )
        self.root = root.resolve()
        if not self.root.is_dir():
            raise RJError(
                "skill_catalog_unavailable", "The bundled RedJohn skill library is missing", status=503
            )
        sig = tuple(
            (str(p.relative_to(self.root)), p.stat().st_mtime_ns)
            for p in sorted(self.root.glob("*/SKILL.md"))
        )
        self._skills: dict[str, LocalSkill] = dict(_load_skills_for_root(str(self.root), sig))
        self._file_listings: dict[str, str] = {}  # per-skill rglob result; library is static

    def get(self, name: str) -> LocalSkill:
        skill = self._skills.get(name)
        if skill is None:
            skill = next((s for s in self._skills.values() if s.skill_id == name), None)
        if skill is None:
            aliases = [s for key, s in self._skills.items() if key.startswith(name + "-")]
            if len(aliases) == 1:
                skill = aliases[0]
        if skill is None:
            raise RJError("skill_unavailable", f"Local skill {name!r} is unavailable", status=404)
        return skill

    def search(self, query: str = "", limit: int = 20) -> list[SkillRef]:
        terms = query.casefold().split()
        matches = [
            skill
            for skill in self._skills.values()
            if all(term in f"{skill.name} {skill.description}".casefold() for term in terms)
        ]
        return [s.reference() for s in matches[: min(max(limit, 1), 50)]]

    def read(self, name: str) -> str:
        skill = self.get(name)
        listing = self._file_listings.get(skill.name)
        if listing is None:
            files = sorted(
                str(p.relative_to(skill.directory))
                for p in skill.directory.rglob("*")
                if p.is_file() and p.suffix in (".md", ".py")
            )
            listing = ", ".join(files)
            self._file_listings[skill.name] = listing
        return skill.content + "\nAvailable skill files: " + listing

    def read_file(self, name: str, relative_path: str) -> str:
        skill = self.get(name)
        path = (skill.directory / relative_path).resolve()
        if not path.is_relative_to(skill.directory.resolve()) or path.suffix not in (".md", ".py"):
            raise RJError("scope_violation", "Skill file is outside the selected skill", status=403)
        if not path.is_file():
            raise RJError("skill_unavailable", "Skill file does not exist", status=404)
        with path.open("rb") as stream:
            data = stream.read(131073)
        if len(data) > 131072:
            raise RJError("skill_file_too_large", "Skill file exceeds 128 KiB", status=422)
        return data.decode("utf-8")

    async def register(self, store: Store) -> None:
        async with store.write() as session:
            for skill in self._skills.values():
                await store.upsert_skill(session, skill.reference())

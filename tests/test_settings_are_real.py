"""
Every setting the project documents must be read by the code. A variable listed in
`.env.example` or in the README's Configuration table that nothing reads describes a
feature that does not exist.
"""

import os
import re

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as f:
        return f.read()


def _source():
    chunks = []
    for top in ("app", "cli"):
        for dirpath, _dirs, files in os.walk(os.path.join(REPO, top)):
            for name in files:
                if name.endswith(".py"):
                    with open(os.path.join(dirpath, name), encoding="utf-8", errors="replace") as f:
                        chunks.append(f.read())
    return "\n".join(chunks)


SOURCE = _source()


def _env_example_names():
    return sorted(set(re.findall(r"(?m)^#?\s*([A-Z][A-Z0-9_]+)=", _read(".env.example"))))


def _readme_table_names():
    text = _read("README.md")
    section = text[text.index("## Configuration"):]
    section = section[:section.index("\n## ", 5)] if "\n## " in section[5:] else section
    return sorted(set(re.findall(r"(?m)^\| `([A-Z][A-Z0-9_]+)` \|", section)))


@pytest.mark.parametrize("name", _env_example_names())
def test_env_example_variable_is_read_by_the_code(name):
    assert re.search(r"[\"']%s[\"']" % re.escape(name), SOURCE), f"{name} is in .env.example but nothing reads it"


@pytest.mark.parametrize("name", _readme_table_names())
def test_readme_configuration_variable_is_read_by_the_code(name):
    assert re.search(r"[\"']%s[\"']" % re.escape(name), SOURCE), f"{name} is in the README but nothing reads it"


def test_the_lists_are_not_empty():
    assert len(_env_example_names()) >= 8 and len(_readme_table_names()) >= 4


def test_api_storage_is_sqlite_or_memory_only():
    from app.utils import database
    assert not hasattr(database, "SUPABASE_SCHEMA")
    assert "supabase" not in _read("app/utils/database.py").lower()

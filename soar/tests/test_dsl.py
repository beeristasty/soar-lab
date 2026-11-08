import pytest, yaml
from pathlib import Path
from app.engine.dsl import Playbook

PB = Path(__file__).parents[1] / "playbooks"

def test_shipped_playbooks_parse():
    for f in PB.glob("*.yaml"):
        Playbook(**yaml.safe_load(f.read_text()))

def test_bad_uses_rejected():
    raw = yaml.safe_load((PB / "pb-001-ssh-bruteforce.yaml").read_text())
    raw["steps"][0]["uses"] = "nonsense"
    with pytest.raises(Exception):
        Playbook(**raw)

def test_unresolved_reference_rejected():
    raw = yaml.safe_load((PB / "pb-001-ssh-bruteforce.yaml").read_text())
    raw["steps"][1]["with"]["ip"] = "{{ steps.nope.value }}"
    with pytest.raises(Exception):
        Playbook(**raw)

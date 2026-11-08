import pytest, yaml
from pathlib import Path
from app.engine import registry

PB = Path(__file__).parents[1] / "playbooks"

def _all_uses():
    for f in PB.glob("*.yaml"):
        for step in yaml.safe_load(f.read_text())["steps"]:
            yield step["uses"]

@pytest.mark.parametrize("uses", sorted(set(_all_uses())))
def test_every_step_connector_resolves(uses):
    mod = registry.get(uses)
    assert callable(mod.run)

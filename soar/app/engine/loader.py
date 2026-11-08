import yaml
from pathlib import Path
from app.engine.dsl import Playbook

def load_all(directory: Path) -> list[Playbook]:
    out = []
    for f in sorted(Path(directory).glob("*.yaml")):
        out.append(Playbook(**yaml.safe_load(f.read_text())))
    return out

def load_one(directory: Path, pb_id: str) -> Playbook:
    for pb in load_all(directory):
        if pb.id == pb_id:
            return pb
    raise KeyError(pb_id)

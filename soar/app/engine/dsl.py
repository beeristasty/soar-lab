import re
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator, model_validator

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
PBID = re.compile(r"^pb-\d{3}-[a-z0-9-]+$")
USES = re.compile(r"^[a-z]+(\.[a-z_]+)+$")
REF = re.compile(r"\{\{\s*([a-zA-Z0-9_.\[\]]+)\s*\}\}")

class Trigger(BaseModel):
    source: Literal["wazuh"] = "wazuh"
    rule_ids: list[int] = Field(min_length=1)
    threshold: int = Field(default=1, ge=1)
    window_seconds: int = Field(default=60, ge=1)

class Step(BaseModel):
    id: str
    uses: str
    with_: dict[str, Any] = Field(default_factory=dict, alias="with")
    when: str | None = None
    on_error: Literal["fail", "continue", "escalate"] = "fail"
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    model_config = {"populate_by_name": True}

    @field_validator("uses")
    @classmethod
    def _uses(cls, v):
        if not USES.match(v):
            raise ValueError(f"uses must be namespace.action, got {v!r}")
        return v

class Playbook(BaseModel):
    id: str
    version: str
    title: str
    description: str = ""
    owner: str = ""
    stakeholders: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    trigger: Trigger
    inputs: list[str] = Field(default_factory=list)
    steps: list[Step] = Field(min_length=1)

    @field_validator("id")
    @classmethod
    def _id(cls, v):
        if not PBID.match(v):
            raise ValueError("id must look like pb-001-name")
        return v

    @field_validator("version")
    @classmethod
    def _ver(cls, v):
        if not SEMVER.match(v):
            raise ValueError("version must be semver")
        return v

    @model_validator(mode="after")
    def _refs(self):
        ids = [s.id for s in self.steps]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate step ids")
        known = set(self.inputs)
        for s in self.steps:
            for blob in [s.when or ""] + [str(v) for v in s.with_.values()]:
                for ref in REF.findall(blob):
                    root = ref.split(".")[0].split("[")[0]
                    if root in ("inputs", "case", "steps", "safe_ips", "dry_run"):
                        continue
                    if ref not in known and root not in known:
                        raise ValueError(f"unresolved reference {ref!r} in step {s.id}")
            known.add(s.id)
        return self

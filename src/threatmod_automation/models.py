from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Component:
    alias: str
    name: str
    kind: str
    boundaries: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DataFlow:
    source: str
    target: str
    direction: str
    description: str = ""
    protocol: str = "unknown"


@dataclass(slots=True)
class ArchitectureModel:
    title: str
    components: dict[str, Component] = field(default_factory=dict)
    data_flows: list[DataFlow] = field(default_factory=list)
    boundaries: set[str] = field(default_factory=set)


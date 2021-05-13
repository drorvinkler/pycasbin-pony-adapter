from dataclasses import dataclass, field


@dataclass
class Filter:
    ptype: list = field(default_factory=list)
    v0: list = field(default_factory=list)
    v1: list = field(default_factory=list)
    v2: list = field(default_factory=list)
    v3: list = field(default_factory=list)
    v4: list = field(default_factory=list)
    v5: list = field(default_factory=list)

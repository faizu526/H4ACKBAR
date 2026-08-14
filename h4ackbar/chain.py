"""
H4ACKBAR chain composer.
Build multi-stage payloads:  seed  →  mutator*  →  encoder*  →  wire
"""

from dataclasses import dataclass, field

from .encoders import apply_chain


@dataclass
class Chain:
    seed: str
    mutators: list[str] = field(default_factory=list)
    encoders: list[str] = field(default_factory=list)

    def render(self) -> str:
        return apply_chain(self.seed, self.mutators + self.encoders)

    def describe(self) -> str:
        return " → ".join(["SEED"] + self.mutators + self.encoders + ["WIRE"])


def preset_chains(seed: str) -> list[Chain]:
    """Battle-tested chains for a given seed."""
    return [
        Chain(seed, [], []),
        Chain(seed, ["case_toggle"], []),
        Chain(seed, ["comment_inline"], []),
        Chain(seed, [], ["url"]),
        Chain(seed, [], ["url_double"]),
        Chain(seed, [], ["url_all"]),
        Chain(seed, ["case_toggle", "comment_inline"], ["url"]),
        Chain(seed, [], ["hex_0x"]),
        Chain(seed, [], ["mysql_CHAR()"]),
        Chain(seed, [], ["pg_CHR||"]),
        Chain(seed, ["comment_versioned"], ["url"]),
        Chain(seed, ["strip_spaces"], ["url_all"]),
        Chain(seed, ["case_toggle"], ["hex_0x", "url"]),
        Chain(seed, ["comment_inline"], ["url_double"]),
    ]

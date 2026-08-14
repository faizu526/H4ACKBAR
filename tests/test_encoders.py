"""Encoder + chain tests."""

import pytest

from h4ackbar.chain import Chain, preset_chains
from h4ackbar.encoders import ENCODERS, apply_chain, hex_grid

SEED = "' OR 1=1-- -"


def test_every_encoder_returns_str_nonempty():
    for name, fn in ENCODERS.items():
        out = fn(SEED)
        assert isinstance(out, str), f"{name} did not return str"
        assert len(out) > 0, f"{name} produced empty"


def test_hex_0x_format():
    out = ENCODERS["hex_0x"](SEED)
    assert out.startswith("0x")
    assert all(c in "0123456789abcdef" for c in out[2:])


def test_mysql_char_format():
    out = ENCODERS["mysql_CHAR()"]("ABC")
    assert out == "CHAR(65,66,67)"


def test_pg_chr_format():
    out = ENCODERS["pg_CHR||"]("ABC")
    assert out == "CHR(65)||CHR(66)||CHR(67)"


def test_url_double_is_double():
    once = ENCODERS["url"](SEED)
    twice = ENCODERS["url_double"](SEED)
    assert once != twice
    assert "%25" in twice  # % double-encoded


def test_apply_chain_composes_left_to_right():
    # hex_0x produces only [0-9a-fx] which are all URL-safe → passthrough
    # But the composition must eliminate raw quote/space from the seed.
    out = apply_chain(SEED, ["hex_0x", "url"])
    assert out.startswith("0x")
    assert "'" not in out
    assert " " not in out
    # order matters: url→hex_0x differs from hex_0x→url
    reversed_out = apply_chain(SEED, ["url", "hex_0x"])
    assert reversed_out != out
    assert reversed_out.startswith("0x")  # still hex, but of the url-encoded form


def test_apply_chain_unknown_encoder_raises():
    with pytest.raises(KeyError):
        apply_chain(SEED, ["NOPE"])


def test_chain_describe():
    c = Chain(SEED, ["case_toggle"], ["url"])
    d = c.describe()
    assert d == "SEED → case_toggle → url → WIRE"


def test_chain_render_matches_apply_chain():
    c = Chain(SEED, ["case_toggle"], ["url"])
    assert c.render() == apply_chain(SEED, ["case_toggle", "url"])


def test_preset_chains_all_render():
    for c in preset_chains(SEED):
        assert isinstance(c.render(), str)


def test_hex_grid_format():
    g = hex_grid("AB")
    # offset  hex  |ascii|
    assert g.startswith("00000000  ")
    assert "|AB" in g


def test_case_toggle_length_preserved():
    for name in ("case_toggle", "case_random"):
        assert len(ENCODERS[name](SEED)) == len(SEED)


def test_comment_inline_replaces_spaces():
    out = ENCODERS["comment_inline"]("A B C")
    assert " " not in out
    assert "/**/" in out

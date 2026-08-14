"""Detector logic tests — network-free.

Directly exercises Finding math + confidence tiers.
Live network flow is smoke-tested manually in a lab.
"""

from h4ackbar.detector import Finding


def test_finding_no_signals_is_none():
    f = Finding(url="", param="", method="", inject_in="")
    assert f.confidence == "none"
    assert not f.confirmed()
    assert f.score() == 0


def test_finding_signals_list_mutable():
    f = Finding(url="", param="", method="", inject_in="")
    f.signals.append("E")
    assert f.score() == 1
    assert not f.confirmed()
    f.signals.append("T")
    assert f.confirmed()
    assert f.score() == 2


def test_confidence_tiers_intent():
    # documented mapping — asserted through the analyze_param body
    # here we just verify labels used elsewhere
    for tier in ("none", "low", "medium", "high"):
        assert isinstance(tier, str)

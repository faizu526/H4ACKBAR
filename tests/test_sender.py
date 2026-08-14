"""Sender input-validation tests. No network hits."""

from h4ackbar.sender import send


def test_bad_scheme_rejected():
    r = send("ftp://x.tld", "GET", "p", "id")
    assert r.status == 0
    assert "http" in (r.error or "").lower()


def test_bad_method_rejected():
    r = send("http://x.tld", "TRACE", "p", "id")
    assert r.status == 0
    assert "method" in (r.error or "").lower()


def test_bad_inject_rejected():
    r = send("http://x.tld", "GET", "p", "id", inject_in="bogus")
    assert r.status == 0
    assert "inject_in" in (r.error or "")

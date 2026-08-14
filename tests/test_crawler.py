"""Crawler helper tests — no network."""

from h4ackbar.crawler import _extract_links, _extract_targets, _same_origin

HTML_LINKS = """
<html><body>
  <a href="/foo?id=1">a1</a>
  <a href="https://example.com/bar?q=x&amp;p=y">a2</a>
  <a href="/plain">a3</a>
  <a href="https://other.com/off">off</a>
</body></html>
"""

HTML_FORM = """
<html><body>
  <form action="/login" method="POST">
    <input name="user" type="text">
    <input name="pass" type="password">
    <input name="csrf" type="hidden">
    <input type="submit" value="go">
  </form>
  <form method="GET" action="/search">
    <input name="q">
  </form>
</body></html>
"""


def test_extract_link_targets_captures_query_params():
    ts = _extract_targets("https://example.com/", HTML_LINKS)
    params = {(t.method, t.param) for t in ts}
    assert ("GET", "id") in params
    assert ("GET", "q") in params
    assert ("GET", "p") in params


def test_extract_form_targets_captures_inputs():
    ts = _extract_targets("https://example.com/", HTML_FORM)
    post_params = {t.param for t in ts if t.method == "POST"}
    assert {"user", "pass", "csrf"} <= post_params
    # submit button excluded
    assert "go" not in post_params

    get_params = {t.param for t in ts if t.method == "GET"}
    assert "q" in get_params


def test_extract_links_absolute():
    ls = _extract_links("https://example.com/", HTML_LINKS)
    assert "https://example.com/foo?id=1" in ls
    assert "https://example.com/plain" in ls
    assert "https://other.com/off" in ls


def test_same_origin():
    assert _same_origin("https://a.com/x", "https://a.com/y")
    assert not _same_origin("https://a.com/", "https://b.com/")
    assert not _same_origin("http://a.com/", "https://a.com/")


def test_form_inject_in_matches_method():
    ts = _extract_targets("https://example.com/", HTML_FORM)
    for t in ts:
        if t.method == "POST":
            assert t.inject_in == "body"
        else:
            assert t.inject_in == "query"

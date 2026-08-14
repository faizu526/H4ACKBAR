"""
H4ACKBAR crawler.
Bounded, same-origin, rate-limited. Harvests:
  - links with query parameters   → GET targets
  - forms with inputs              → POST targets
  - robots.txt disallow paths      → skipped

Never follows off-scope hosts. Never recurses without depth limit.
Never floods — configurable delay between requests.
"""

import time
import urllib.parse
from collections import deque
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Callable
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup


@dataclass
class Target:
    url: str
    method: str          # GET | POST
    param: str
    inject_in: str = "query"   # query | body
    source: str = ""          # discovery path


@dataclass
class CrawlReport:
    pages_visited: List[str] = field(default_factory=list)
    targets: List[Target] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_s: float = 0.0


def _same_origin(a: str, b: str) -> bool:
    pa = urllib.parse.urlparse(a)
    pb = urllib.parse.urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def _fetch(url: str, timeout: float = 10.0) -> Optional[requests.Response]:
    try:
        return requests.get(
            url,
            headers={"User-Agent": "H4ACKBAR/1.0 (authorized-testing)"},
            timeout=timeout,
            allow_redirects=True,
            verify=True,
        )
    except requests.RequestException:
        return None


def _load_robots(base: str) -> RobotFileParser:
    rp = RobotFileParser()
    p = urllib.parse.urlparse(base)
    robots_url = f"{p.scheme}://{p.netloc}/robots.txt"
    try:
        rp.set_url(robots_url)
        rp.read()
    except Exception:
        pass
    return rp


def _extract_targets(page_url: str, html: str) -> List[Target]:
    out: List[Target] = []
    soup = BeautifulSoup(html, "lxml")

    # 1) links with query params
    for a in soup.find_all("a", href=True):
        href = urllib.parse.urljoin(page_url, a["href"])
        pu = urllib.parse.urlparse(href)
        if not pu.query:
            continue
        clean = f"{pu.scheme}://{pu.netloc}{pu.path}"
        for k, _ in urllib.parse.parse_qsl(pu.query, keep_blank_values=True):
            out.append(Target(url=clean, method="GET", param=k,
                              inject_in="query", source=f"link({href})"))

    # 2) forms
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        action = urllib.parse.urljoin(page_url, action)
        method = (form.get("method") or "GET").upper()
        for field_ in form.find_all(["input", "textarea", "select"]):
            name = field_.get("name")
            if not name:
                continue
            typ = (field_.get("type") or "").lower()
            if typ in {"submit", "button", "image", "reset", "file"}:
                continue
            inject_in = "body" if method == "POST" else "query"
            out.append(Target(url=action, method=method, param=name,
                              inject_in=inject_in, source=f"form({action})"))

    return out


def _extract_links(page_url: str, html: str) -> List[str]:
    soup = BeautifulSoup(html, "lxml")
    out = []
    for a in soup.find_all("a", href=True):
        href = urllib.parse.urljoin(page_url, a["href"])
        # strip fragment
        href = urllib.parse.urldefrag(href)[0]
        out.append(href)
    return out


def crawl(seed_url: str,
          max_pages: int = 25,
          max_depth: int = 2,
          delay_ms: int = 250,
          respect_robots: bool = True,
          progress: Optional[Callable[[str], None]] = None) -> CrawlReport:
    """
    BFS crawl. Same-origin only. Bounded by max_pages / max_depth.
    """
    report = CrawlReport()
    t0 = time.perf_counter()

    if not (seed_url.startswith("http://") or seed_url.startswith("https://")):
        report.errors.append("seed URL must be http(s)://")
        return report

    rp = _load_robots(seed_url) if respect_robots else None
    visited: Set[str] = set()
    seen_targets: Set[tuple] = set()
    queue: deque = deque([(seed_url, 0)])

    while queue and len(report.pages_visited) < max_pages:
        url, depth = queue.popleft()
        if url in visited:
            continue
        if not _same_origin(seed_url, url):
            continue
        if rp is not None and not rp.can_fetch("H4ACKBAR", url):
            report.errors.append(f"robots-disallow: {url}")
            continue

        visited.add(url)
        if progress:
            progress(f"[crawl d={depth}] GET {url}")

        r = _fetch(url)
        if r is None:
            report.errors.append(f"fetch fail: {url}")
            continue
        report.pages_visited.append(url)

        ctype = r.headers.get("Content-Type", "")
        if "html" not in ctype.lower():
            continue

        # harvest targets
        for t in _extract_targets(url, r.text):
            key = (t.url, t.method, t.param, t.inject_in)
            if key in seen_targets:
                continue
            seen_targets.add(key)
            report.targets.append(t)

        # queue links
        if depth < max_depth:
            for link in _extract_links(url, r.text):
                if link in visited:
                    continue
                if not _same_origin(seed_url, link):
                    continue
                queue.append((link, depth + 1))

        time.sleep(delay_ms / 1000.0)

    report.duration_s = round(time.perf_counter() - t0, 2)
    return report

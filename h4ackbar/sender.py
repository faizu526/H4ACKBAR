"""
H4ACKBAR HTTP sender.
Manual fire only. No auto-scan. No auto-loop.
Authorized targets only.
"""

import time
from dataclasses import dataclass, field
from typing import Optional, Dict

import requests


@dataclass
class SendResult:
    status: int
    elapsed_ms: int
    length: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: Optional[str] = None


def send(url: str,
         method: str,
         payload: str,
         param: str,
         inject_in: str = "query",   # query | body | header | path
         headers: Optional[Dict[str, str]] = None,
         timeout: float = 15.0,
         verify_tls: bool = True) -> SendResult:
    """
    inject_in:
      query  → ?param=payload
      body   → form field
      header → header value (name = param)
      path   → /url/payload
    """
    method = method.upper()
    if method not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
        return SendResult(0, 0, 0, {}, "", f"bad method: {method}")

    if not (url.startswith("http://") or url.startswith("https://")):
        return SendResult(0, 0, 0, {}, "", "URL must start with http(s)://")

    hdrs = {"User-Agent": "H4ACKBAR/1.0 (authorized-testing)"}
    if headers:
        hdrs.update(headers)

    t0 = time.perf_counter()
    try:
        if inject_in == "query":
            r = requests.request(method, url, params={param: payload},
                                 headers=hdrs, timeout=timeout,
                                 allow_redirects=False, verify=verify_tls)
        elif inject_in == "body":
            r = requests.request(method, url, data={param: payload},
                                 headers=hdrs, timeout=timeout,
                                 allow_redirects=False, verify=verify_tls)
        elif inject_in == "header":
            h = dict(hdrs)
            h[param] = payload
            r = requests.request(method, url, headers=h, timeout=timeout,
                                 allow_redirects=False, verify=verify_tls)
        elif inject_in == "path":
            full = url.rstrip("/") + "/" + payload
            r = requests.request(method, full, headers=hdrs, timeout=timeout,
                                 allow_redirects=False, verify=verify_tls)
        else:
            return SendResult(0, 0, 0, {}, "", f"bad inject_in: {inject_in}")

        dt = int((time.perf_counter() - t0) * 1000)
        return SendResult(r.status_code, dt, len(r.content),
                          dict(r.headers), r.text[:20000])
    except requests.RequestException as e:
        dt = int((time.perf_counter() - t0) * 1000)
        return SendResult(0, dt, 0, {}, "", str(e))

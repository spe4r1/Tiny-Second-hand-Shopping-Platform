import http.cookiejar
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def request(opener, url, data=None, method=None):
    encoded = None
    headers = {}
    if data is not None:
        encoded = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=encoded, headers=headers, method=method)
    try:
        with opener.open(req, timeout=5) as res:
            body = res.read().decode("utf-8", "replace")
            return res.status, dict(res.headers), body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return exc.code, dict(exc.headers), body


def csrf_from(body):
    match = re.search(r'name="csrf_token" value="([^"]+)"', body)
    assert match, "CSRF token not found"
    return match.group(1)


def main():
    port = free_port()
    env = os.environ.copy()
    env["PORT"] = str(port)
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "app.py")],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        for _ in range(40):
            try:
                status, headers, body = request(opener, base + "/")
                if status == 200:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise AssertionError("server did not start")

        assert status == 200
        assert "Content-Security-Policy" in headers

        username = "testuser" + str(int(time.time()))[-6:]
        status, _, _ = request(
            opener,
            base + "/register",
            {
                "username": username,
                "password": "Secure12345",
                "display_name": "테스터",
                "phone": "010-5555-1212",
            },
        )
        assert status in (200, 303)

        status, headers, _ = request(opener, base + "/login", {"username": username, "password": "Secure12345"})
        assert status in (200, 303)
        assert any(cookie.name == "tiny_session" for cookie in jar)

        status, _, body = request(opener, base + "/products/new")
        assert status == 200
        csrf = csrf_from(body)

        payload = {
            "title": "<script>alert(1)</script>",
            "description": "보안 테스트용 상품 설명입니다.",
            "category": "digital",
            "condition": "good",
            "price": "12345",
            "location": "서울",
            "image_url": "https://example.com/item.png",
        }
        status, _, _ = request(opener, base + "/products", payload)
        assert status == 403, "missing CSRF should be rejected"

        no_redirect = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)
        payload["csrf_token"] = csrf
        status, headers, _ = request(no_redirect, base + "/products", payload)
        assert status in (200, 303)
        location = headers.get("Location", "")
        assert location.startswith("/products/")

        status, _, body = request(opener, base + location)
        assert status == 200
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
        assert "<script>alert(1)</script>" not in body

        bob = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        status, _, _ = request(bob, base + "/login", {"username": "bob", "password": "Bob!234567"})
        assert status in (200, 303)
        status, _, edit_body = request(bob, base + "/products/1/edit")
        assert status == 403
        assert "본인이 등록한 상품만" in edit_body

        print("smoke tests passed")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()

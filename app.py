#!/usr/bin/env python3
import base64
import hashlib
import hmac
import html
import os
import re
import secrets
import sqlite3
import sys
import time
import urllib.parse
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parent
DB_PATH = APP_ROOT / "data" / "shop.sqlite3"
SESSION_COOKIE = "tiny_session"
SESSION_TTL = 60 * 60 * 4
MAX_BODY = 1024 * 1024
PBKDF2_ITERATIONS = 210_000
CATEGORIES = ["digital", "fashion", "home", "book", "sports", "etc"]
CONDITIONS = ["new", "like-new", "good", "fair"]
STATUSES = ["selling", "reserved", "sold"]


def now() -> int:
    return int(time.time())


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def init_db() -> None:
    with db() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                condition TEXT NOT NULL,
                price INTEGER NOT NULL,
                location TEXT NOT NULL,
                image_url TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'selling',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS favorites (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, product_id)
            );
            CREATE TABLE IF NOT EXISTS cart_items (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, product_id)
            );
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                buyer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                total_price INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS order_items (
                order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
                product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
                seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
                price INTEGER NOT NULL,
                PRIMARY KEY (order_id, product_id)
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT NOT NULL,
                ip TEXT NOT NULL,
                attempted_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            uid1 = create_user(con, "alice", "Alice!2345", "앨리스", "010-1234-0001")
            uid2 = create_user(con, "bob", "Bob!234567", "밥", "010-1234-0002")
            seed_product(
                con,
                uid1,
                "기계식 키보드",
                "저소음 적축 키보드입니다. 깨끗하게 사용했고 구성품 모두 포함됩니다.",
                "digital",
                "good",
                45000,
                "서울 마포구",
                "https://images.unsplash.com/photo-1587829741301-dc798b83add3?w=900",
            )
            seed_product(
                con,
                uid2,
                "미니 선반",
                "원룸에서 쓰기 좋은 우드 선반입니다. 직접 거래를 선호합니다.",
                "home",
                "like-new",
                18000,
                "경기 성남시",
                "https://images.unsplash.com/photo-1594026112284-02bb6f3352fe?w=900",
            )


def create_user(con: sqlite3.Connection, username: str, password: str, display_name: str, phone: str) -> int:
    password_hash = hash_password(password)
    cur = con.execute(
        "INSERT INTO users(username, password_hash, display_name, phone, created_at) VALUES (?, ?, ?, ?, ?)",
        (username, password_hash, display_name, phone, now()),
    )
    return int(cur.lastrowid)


def seed_product(con, seller_id, title, description, category, condition, price, location, image_url):
    con.execute(
        """
        INSERT INTO products(seller_id, title, description, category, condition, price, location, image_url, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'selling', ?, ?)
        """,
        (seller_id, title, description, category, condition, price, location, image_url, now(), now()),
    )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_b64, digest_b64 = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def money(value) -> str:
    return f"{int(value):,}원"


def row_get(row, key: str, default=""):
    if row is None:
        return default
    if isinstance(row, dict):
        return row.get(key, default)
    return row[key] if key in row.keys() else default


def clip(value: str, max_len: int) -> str:
    return value.strip()[:max_len]


def validate_username(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,24}", value))


def validate_phone(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9+\- ]{8,20}", value))


def validate_image_url(value: str) -> bool:
    if not value:
        return True
    parsed = urllib.parse.urlparse(value)
    return parsed.scheme in {"https", "http"} and bool(parsed.netloc) and len(value) <= 400


def product_query(params):
    q = clip(params.get("q", [""])[0], 80)
    category = params.get("category", [""])[0]
    status = params.get("status", ["selling"])[0]
    clauses = []
    values = []
    if q:
        clauses.append("(p.title LIKE ? OR p.description LIKE ? OR p.location LIKE ?)")
        like = f"%{q}%"
        values.extend([like, like, like])
    if category in CATEGORIES:
        clauses.append("p.category = ?")
        values.append(category)
    if status in STATUSES:
        clauses.append("p.status = ?")
        values.append(status)
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    return where, values, q, category, status


class App(BaseHTTPRequestHandler):
    server_version = "TinySecondhand/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), fmt % args))

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def route(self, method: str):
        self.parsed = urllib.parse.urlparse(self.path)
        self.params = urllib.parse.parse_qs(self.parsed.query)
        self.current_user, self.csrf_token = self.load_session()
        try:
            routes = [
                ("GET", r"^/$", self.home),
                ("GET", r"^/login$", self.login_form),
                ("POST", r"^/login$", self.login_submit),
                ("GET", r"^/register$", self.register_form),
                ("POST", r"^/register$", self.register_submit),
                ("POST", r"^/logout$", self.logout),
                ("GET", r"^/products/new$", self.product_form),
                ("POST", r"^/products$", self.product_create),
                ("GET", r"^/products/([0-9]+)$", self.product_detail),
                ("GET", r"^/products/([0-9]+)/edit$", self.product_edit_form),
                ("POST", r"^/products/([0-9]+)/edit$", self.product_update),
                ("POST", r"^/products/([0-9]+)/favorite$", self.favorite_toggle),
                ("POST", r"^/products/([0-9]+)/cart$", self.cart_add),
                ("POST", r"^/products/([0-9]+)/status$", self.status_update),
                ("POST", r"^/products/([0-9]+)/message$", self.message_send),
                ("GET", r"^/dashboard$", self.dashboard),
                ("GET", r"^/cart$", self.cart),
                ("POST", r"^/cart/remove$", self.cart_remove),
                ("POST", r"^/checkout$", self.checkout),
                ("GET", r"^/orders$", self.orders),
                ("GET", r"^/messages$", self.messages),
                ("GET", r"^/static/style.css$", self.static_style),
                ("GET", r"^/static/app.js$", self.static_js),
            ]
            for route_method, pattern, handler in routes:
                match = re.match(pattern, self.parsed.path)
                if method == route_method and match:
                    return handler(*match.groups())
            self.not_found()
        except ValueError as exc:
            self.render("요청 오류", f"<div class='alert'>{esc(exc)}</div>", status=400)
        except PermissionError as exc:
            self.render("권한 오류", f"<div class='alert'>{esc(exc)}</div>", status=403)

    def load_session(self):
        raw_cookie = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie(raw_cookie)
        morsel = jar.get(SESSION_COOKIE)
        if not morsel:
            return None, ""
        th = token_hash(morsel.value)
        with db() as con:
            row = con.execute(
                """
                SELECT s.csrf_token, s.expires_at, u.*
                FROM sessions s JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = ?
                """,
                (th,),
            ).fetchone()
            if not row or row["expires_at"] < now():
                con.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
                return None, ""
            return row, row["csrf_token"]

    def require_user(self):
        if not self.current_user:
            raise PermissionError("로그인이 필요합니다.")
        return self.current_user

    def read_form(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_BODY:
            raise ValueError("요청 본문이 너무 큽니다.")
        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = {k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}
        if self.command == "POST" and self.current_user:
            sent = form.get("csrf_token", "")
            if not hmac.compare_digest(sent, self.csrf_token):
                raise PermissionError("CSRF 토큰 검증에 실패했습니다.")
        return form

    def send_common_headers(self, status=200, content_type="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' https: data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        )

    def write_html(self, body: str, status=200):
        data = body.encode("utf-8")
        self.send_common_headers(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, target: str):
        self.send_response(303)
        self.send_header("Location", target)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def render(self, title: str, content: str, status=200):
        user_nav = ""
        if self.current_user:
            user_nav = f"""
            <a href="/products/new">판매 등록</a>
            <a href="/cart">장바구니</a>
            <a href="/orders">주문</a>
            <a href="/messages">문의</a>
            <a href="/dashboard">내 상점</a>
            <form method="post" action="/logout" class="inline">
              {self.csrf_input()}
              <button>로그아웃</button>
            </form>
            """
        else:
            user_nav = '<a href="/login">로그인</a><a class="button" href="/register">회원가입</a>'
        page = f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} - Tiny Second-hand</title>
  <link rel="stylesheet" href="/static/style.css">
  <script src="/static/app.js" defer></script>
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">Tiny Second-hand</a>
    <nav>{user_nav}</nav>
  </header>
  <main>{content}</main>
</body>
</html>"""
        self.write_html(page, status)

    def csrf_input(self) -> str:
        return f'<input type="hidden" name="csrf_token" value="{esc(self.csrf_token)}">'

    def home(self):
        where, values, q, category, status = product_query(self.params)
        with db() as con:
            rows = con.execute(
                f"""
                SELECT p.*, u.display_name AS seller_name,
                EXISTS(SELECT 1 FROM favorites f WHERE f.product_id = p.id AND f.user_id = ?) AS favored
                FROM products p JOIN users u ON u.id = p.seller_id
                {where}
                ORDER BY p.created_at DESC LIMIT 60
                """,
                ([self.current_user["id"] if self.current_user else -1] + values),
            ).fetchall()
        category_options = "".join(
            f'<option value="{c}" {"selected" if c == category else ""}>{category_label(c)}</option>' for c in CATEGORIES
        )
        cards = "".join(self.product_card(row) for row in rows) or "<p class='empty'>조건에 맞는 상품이 없습니다.</p>"
        content = f"""
        <section class="hero">
          <div>
            <p class="eyebrow">Secure coding project</p>
            <h1>안전한 중고거래 상점</h1>
            <p>회원 가입, 판매 등록, 찜, 장바구니, 주문, 문의까지 포함한 Tiny Second-hand Shopping Platform입니다.</p>
          </div>
          <div class="secure-points">
            <strong>적용 보안</strong>
            <span>CSRF</span><span>SQL Injection 방어</span><span>XSS 방어</span><span>IDOR 방어</span>
          </div>
        </section>
        <form class="filters" method="get" action="/">
          <input name="q" value="{esc(q)}" placeholder="상품명, 설명, 지역 검색" maxlength="80">
          <select name="category"><option value="">전체 카테고리</option>{category_options}</select>
          <select name="status">
            <option value="selling" {"selected" if status == "selling" else ""}>판매중</option>
            <option value="reserved" {"selected" if status == "reserved" else ""}>예약중</option>
            <option value="sold" {"selected" if status == "sold" else ""}>판매완료</option>
          </select>
          <button>검색</button>
        </form>
        <section class="grid">{cards}</section>
        """
        self.render("상품 목록", content)

    def product_card(self, row) -> str:
        seller = row_get(row, "seller_name", "판매자")
        return f"""
        <article class="product-card">
          <a href="/products/{row['id']}">
            <img src="{esc(row['image_url'])}" alt="{esc(row['title'])}">
            <div class="card-body">
              <span class="badge">{status_label(row['status'])}</span>
              <h2>{esc(row['title'])}</h2>
              <p>{esc(row['location'])} · {esc(seller)}</p>
              <strong>{money(row['price'])}</strong>
            </div>
          </a>
        </article>
        """

    def login_form(self):
        self.render("로그인", auth_form("login", "로그인", "계정이 없나요?", "/register", "회원가입"))

    def register_form(self):
        self.render("회원가입", auth_form("register", "회원가입", "이미 계정이 있나요?", "/login", "로그인"))

    def login_submit(self):
        form = self.read_form()
        username = clip(form.get("username", ""), 24)
        password = form.get("password", "")
        ip = self.client_address[0]
        with db() as con:
            since = now() - 15 * 60
            attempts = con.execute(
                "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND ip = ? AND attempted_at > ?",
                (username, ip, since),
            ).fetchone()[0]
            if attempts >= 8:
                raise PermissionError("로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.")
            con.execute("INSERT INTO login_attempts(username, ip, attempted_at) VALUES (?, ?, ?)", (username, ip, now()))
            user = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                self.render("로그인 실패", "<div class='alert'>아이디 또는 비밀번호가 올바르지 않습니다.</div>" + auth_form("login", "로그인", "계정이 없나요?", "/register", "회원가입"), status=401)
                return
            token = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(32)
            con.execute(
                "INSERT INTO sessions(token_hash, user_id, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
                (token_hash(token), user["id"], csrf, now() + SESSION_TTL, now()),
            )
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_TTL}")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def register_submit(self):
        form = self.read_form()
        username = clip(form.get("username", ""), 24)
        password = form.get("password", "")
        display_name = clip(form.get("display_name", ""), 40)
        phone = clip(form.get("phone", ""), 20)
        errors = []
        if not validate_username(username):
            errors.append("아이디는 영문, 숫자, 밑줄 3-24자만 사용할 수 있습니다.")
        if len(password) < 10 or not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9]", password):
            errors.append("비밀번호는 10자 이상이며 영문과 숫자를 포함해야 합니다.")
        if not (2 <= len(display_name) <= 40):
            errors.append("표시 이름은 2-40자여야 합니다.")
        if not validate_phone(phone):
            errors.append("연락처 형식이 올바르지 않습니다.")
        if errors:
            self.render("회원가입 오류", alerts(errors) + auth_form("register", "회원가입", "이미 계정이 있나요?", "/login", "로그인"), status=400)
            return
        try:
            with db() as con:
                create_user(con, username, password, display_name, phone)
        except sqlite3.IntegrityError:
            self.render("회원가입 오류", "<div class='alert'>이미 사용 중인 아이디입니다.</div>" + auth_form("register", "회원가입", "이미 계정이 있나요?", "/login", "로그인"), status=409)
            return
        self.redirect("/login")

    def logout(self):
        self.require_user()
        self.read_form()
        raw_cookie = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie(raw_cookie)
        morsel = jar.get(SESSION_COOKIE)
        if morsel:
            with db() as con:
                con.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(morsel.value),))
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", f"{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
        self.end_headers()

    def product_form(self):
        self.require_user()
        self.render("판매 등록", product_form_html(self.csrf_input(), "/products", None))

    def product_create(self):
        user = self.require_user()
        form = self.read_form()
        data = validate_product_form(form)
        with db() as con:
            cur = con.execute(
                """
                INSERT INTO products(seller_id, title, description, category, condition, price, location, image_url, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'selling', ?, ?)
                """,
                (user["id"], data["title"], data["description"], data["category"], data["condition"], data["price"], data["location"], data["image_url"], now(), now()),
            )
            log(con, user["id"], "create_product", f"product:{cur.lastrowid}")
        self.redirect(f"/products/{cur.lastrowid}")

    def product_detail(self, product_id):
        pid = int(product_id)
        with db() as con:
            product = con.execute(
                "SELECT p.*, u.display_name AS seller_name, u.phone AS seller_phone FROM products p JOIN users u ON u.id = p.seller_id WHERE p.id = ?",
                (pid,),
            ).fetchone()
            if not product:
                self.not_found()
                return
            if self.current_user:
                messages = con.execute(
                    """
                    SELECT m.*, u.display_name AS sender_name
                    FROM messages m JOIN users u ON u.id = m.sender_id
                    WHERE m.product_id = ? AND (m.sender_id = ? OR m.receiver_id = ?)
                    ORDER BY m.created_at DESC LIMIT 20
                    """,
                    (pid, self.current_user["id"], self.current_user["id"]),
                ).fetchall()
            else:
                messages = []
        controls = ""
        if self.current_user:
            if self.current_user["id"] == product["seller_id"]:
                controls = f"""
                <div class="actions">
                  <a class="button" href="/products/{pid}/edit">수정</a>
                  <form method="post" action="/products/{pid}/status">{self.csrf_input()}
                    <select name="status">
                      {status_options(product['status'])}
                    </select>
                    <button>상태 변경</button>
                  </form>
                </div>
                """
            else:
                controls = f"""
                <div class="actions">
                  <form method="post" action="/products/{pid}/favorite">{self.csrf_input()}<button>찜하기/취소</button></form>
                  <form method="post" action="/products/{pid}/cart">{self.csrf_input()}<button>장바구니 담기</button></form>
                </div>
                <form class="panel" method="post" action="/products/{pid}/message">
                  {self.csrf_input()}
                  <label>판매자에게 문의<textarea name="body" maxlength="500" required></textarea></label>
                  <button>문의 보내기</button>
                </form>
                """
        message_list = "".join(f"<li><strong>{esc(m['sender_name'])}</strong> {esc(m['body'])}</li>" for m in messages) or "<li>아직 문의가 없습니다.</li>"
        content = f"""
        <section class="detail">
          <img src="{esc(product['image_url'])}" alt="{esc(product['title'])}">
          <div>
            <span class="badge">{status_label(product['status'])}</span>
            <h1>{esc(product['title'])}</h1>
            <p class="price">{money(product['price'])}</p>
            <p>{esc(product['description'])}</p>
            <dl>
              <dt>카테고리</dt><dd>{category_label(product['category'])}</dd>
              <dt>상태</dt><dd>{condition_label(product['condition'])}</dd>
              <dt>지역</dt><dd>{esc(product['location'])}</dd>
              <dt>판매자</dt><dd>{esc(product['seller_name'])}</dd>
            </dl>
            {controls}
          </div>
        </section>
        <section class="panel"><h2>상품 문의</h2><ul class="messages">{message_list}</ul></section>
        """
        self.render(product["title"], content)

    def product_edit_form(self, product_id):
        user = self.require_user()
        product = get_product_or_404(int(product_id))
        if product["seller_id"] != user["id"]:
            raise PermissionError("본인이 등록한 상품만 수정할 수 있습니다.")
        self.render("상품 수정", product_form_html(self.csrf_input(), f"/products/{product['id']}/edit", product))

    def product_update(self, product_id):
        user = self.require_user()
        product = get_product_or_404(int(product_id))
        if product["seller_id"] != user["id"]:
            raise PermissionError("본인이 등록한 상품만 수정할 수 있습니다.")
        form = self.read_form()
        data = validate_product_form(form)
        with db() as con:
            con.execute(
                """
                UPDATE products SET title = ?, description = ?, category = ?, condition = ?, price = ?, location = ?, image_url = ?, updated_at = ?
                WHERE id = ? AND seller_id = ?
                """,
                (data["title"], data["description"], data["category"], data["condition"], data["price"], data["location"], data["image_url"], now(), product["id"], user["id"]),
            )
            log(con, user["id"], "update_product", f"product:{product['id']}")
        self.redirect(f"/products/{product['id']}")

    def favorite_toggle(self, product_id):
        user = self.require_user()
        self.read_form()
        pid = int(product_id)
        product = get_product_or_404(pid)
        if product["seller_id"] == user["id"]:
            raise ValueError("본인 상품은 찜할 수 없습니다.")
        with db() as con:
            exists = con.execute("SELECT 1 FROM favorites WHERE user_id = ? AND product_id = ?", (user["id"], pid)).fetchone()
            if exists:
                con.execute("DELETE FROM favorites WHERE user_id = ? AND product_id = ?", (user["id"], pid))
            else:
                con.execute("INSERT INTO favorites(user_id, product_id, created_at) VALUES (?, ?, ?)", (user["id"], pid, now()))
        self.redirect(f"/products/{pid}")

    def cart_add(self, product_id):
        user = self.require_user()
        self.read_form()
        pid = int(product_id)
        product = get_product_or_404(pid)
        if product["seller_id"] == user["id"] or product["status"] != "selling":
            raise ValueError("구매 가능한 상품만 장바구니에 담을 수 있습니다.")
        with db() as con:
            con.execute("INSERT OR IGNORE INTO cart_items(user_id, product_id, created_at) VALUES (?, ?, ?)", (user["id"], pid, now()))
        self.redirect("/cart")

    def status_update(self, product_id):
        user = self.require_user()
        form = self.read_form()
        status = form.get("status", "")
        if status not in STATUSES:
            raise ValueError("상태 값이 올바르지 않습니다.")
        product = get_product_or_404(int(product_id))
        if product["seller_id"] != user["id"]:
            raise PermissionError("본인이 등록한 상품만 상태를 변경할 수 있습니다.")
        with db() as con:
            con.execute("UPDATE products SET status = ?, updated_at = ? WHERE id = ? AND seller_id = ?", (status, now(), product["id"], user["id"]))
            log(con, user["id"], "status_product", f"product:{product['id']}:{status}")
        self.redirect(f"/products/{product['id']}")

    def message_send(self, product_id):
        user = self.require_user()
        form = self.read_form()
        product = get_product_or_404(int(product_id))
        if product["seller_id"] == user["id"]:
            raise ValueError("본인 상품에는 문의를 보낼 수 없습니다.")
        body = clip(form.get("body", ""), 500)
        if len(body) < 2:
            raise ValueError("문의 내용은 2자 이상이어야 합니다.")
        with db() as con:
            con.execute(
                "INSERT INTO messages(product_id, sender_id, receiver_id, body, created_at) VALUES (?, ?, ?, ?, ?)",
                (product["id"], user["id"], product["seller_id"], body, now()),
            )
        self.redirect(f"/products/{product['id']}")

    def dashboard(self):
        user = self.require_user()
        with db() as con:
            products = con.execute("SELECT * FROM products WHERE seller_id = ? ORDER BY created_at DESC", (user["id"],)).fetchall()
            favs = con.execute(
                "SELECT p.* FROM favorites f JOIN products p ON p.id = f.product_id WHERE f.user_id = ? ORDER BY f.created_at DESC",
                (user["id"],),
            ).fetchall()
        content = f"""
        <section class="panel">
          <h1>{esc(user['display_name'])}님의 상점</h1>
          <p>등록 상품 {len(products)}개 · 찜한 상품 {len(favs)}개</p>
        </section>
        <h2>내 판매 상품</h2><section class="grid">{''.join(self.product_card(p) for p in products) or "<p class='empty'>등록 상품이 없습니다.</p>"}</section>
        <h2>찜한 상품</h2><section class="grid">{''.join(self.product_card(p) for p in favs) or "<p class='empty'>찜한 상품이 없습니다.</p>"}</section>
        """
        self.render("내 상점", content)

    def cart(self):
        user = self.require_user()
        with db() as con:
            rows = con.execute(
                "SELECT p.* FROM cart_items c JOIN products p ON p.id = c.product_id WHERE c.user_id = ? ORDER BY c.created_at DESC",
                (user["id"],),
            ).fetchall()
        total = sum(int(r["price"]) for r in rows if r["status"] == "selling")
        items = "".join(cart_row(r, self.csrf_input()) for r in rows) or "<p class='empty'>장바구니가 비어 있습니다.</p>"
        content = f"""
        <section class="panel">
          <h1>장바구니</h1>
          {items}
          <div class="cart-total"><strong>합계 {money(total)}</strong></div>
          <form method="post" action="/checkout">{self.csrf_input()}<button {'disabled' if total == 0 else ''}>구매 확정</button></form>
        </section>
        """
        self.render("장바구니", content)

    def cart_remove(self):
        user = self.require_user()
        form = self.read_form()
        pid = int(form.get("product_id", "0"))
        with db() as con:
            con.execute("DELETE FROM cart_items WHERE user_id = ? AND product_id = ?", (user["id"], pid))
        self.redirect("/cart")

    def checkout(self):
        user = self.require_user()
        self.read_form()
        with db() as con:
            rows = con.execute(
                "SELECT p.* FROM cart_items c JOIN products p ON p.id = c.product_id WHERE c.user_id = ? AND p.status = 'selling' AND p.seller_id != ?",
                (user["id"], user["id"]),
            ).fetchall()
            if not rows:
                raise ValueError("구매 가능한 상품이 없습니다.")
            total = sum(int(r["price"]) for r in rows)
            cur = con.execute("INSERT INTO orders(buyer_id, total_price, status, created_at) VALUES (?, ?, 'paid', ?)", (user["id"], total, now()))
            order_id = int(cur.lastrowid)
            for row in rows:
                con.execute("INSERT INTO order_items(order_id, product_id, seller_id, price) VALUES (?, ?, ?, ?)", (order_id, row["id"], row["seller_id"], row["price"]))
                con.execute("UPDATE products SET status = 'sold', updated_at = ? WHERE id = ?", (now(), row["id"]))
            con.execute("DELETE FROM cart_items WHERE user_id = ?", (user["id"],))
            log(con, user["id"], "checkout", f"order:{order_id}")
        self.redirect("/orders")

    def orders(self):
        user = self.require_user()
        with db() as con:
            rows = con.execute("SELECT * FROM orders WHERE buyer_id = ? ORDER BY created_at DESC", (user["id"],)).fetchall()
        cards = "".join(f"<article class='order'><strong>주문 #{r['id']}</strong><span>{money(r['total_price'])}</span><span>{esc(r['status'])}</span></article>" for r in rows) or "<p class='empty'>주문 내역이 없습니다.</p>"
        self.render("주문 내역", f"<section class='panel'><h1>주문 내역</h1>{cards}</section>")

    def messages(self):
        user = self.require_user()
        with db() as con:
            rows = con.execute(
                """
                SELECT m.*, p.title, u.display_name AS sender_name
                FROM messages m JOIN products p ON p.id = m.product_id JOIN users u ON u.id = m.sender_id
                WHERE m.sender_id = ? OR m.receiver_id = ?
                ORDER BY m.created_at DESC LIMIT 100
                """,
                (user["id"], user["id"]),
            ).fetchall()
        items = "".join(f"<li><a href='/products/{r['product_id']}'>{esc(r['title'])}</a> <strong>{esc(r['sender_name'])}</strong> {esc(r['body'])}</li>" for r in rows) or "<li>문의 내역이 없습니다.</li>"
        self.render("문의 내역", f"<section class='panel'><h1>문의 내역</h1><ul class='messages'>{items}</ul></section>")

    def static_style(self):
        self.static_file("static/style.css", "text/css; charset=utf-8")

    def static_js(self):
        self.static_file("static/app.js", "application/javascript; charset=utf-8")

    def static_file(self, rel: str, content_type: str):
        data = (APP_ROOT / rel).read_bytes()
        self.send_common_headers(200, content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def not_found(self):
        self.render("404", "<div class='alert'>페이지를 찾을 수 없습니다.</div>", status=404)


def auth_form(action: str, title: str, help_text: str, link: str, link_text: str) -> str:
    extra = ""
    if action == "register":
        extra = """
        <label>표시 이름<input name="display_name" maxlength="40" required></label>
        <label>연락처<input name="phone" maxlength="20" required></label>
        """
    return f"""
    <section class="auth panel">
      <h1>{title}</h1>
      <form method="post" action="/{action}">
        <label>아이디<input name="username" maxlength="24" autocomplete="username" required></label>
        <label>비밀번호<input name="password" type="password" minlength="10" autocomplete="current-password" required></label>
        {extra}
        <button>{title}</button>
      </form>
      <p>{help_text} <a href="{link}">{link_text}</a></p>
    </section>
    """


def validate_product_form(form):
    title = clip(form.get("title", ""), 80)
    description = clip(form.get("description", ""), 1500)
    category = form.get("category", "")
    condition = form.get("condition", "")
    location = clip(form.get("location", ""), 80)
    image_url = clip(form.get("image_url", ""), 400) or "https://images.unsplash.com/photo-1516321318423-f06f85e504b3?w=900"
    try:
        price = int(form.get("price", "0"))
    except ValueError:
        price = 0
    errors = []
    if not (2 <= len(title) <= 80):
        errors.append("상품명은 2-80자여야 합니다.")
    if not (10 <= len(description) <= 1500):
        errors.append("상품 설명은 10-1500자여야 합니다.")
    if category not in CATEGORIES:
        errors.append("카테고리가 올바르지 않습니다.")
    if condition not in CONDITIONS:
        errors.append("상품 상태가 올바르지 않습니다.")
    if not (100 <= price <= 100_000_000):
        errors.append("가격은 100원 이상 1억원 이하로 입력해야 합니다.")
    if not (2 <= len(location) <= 80):
        errors.append("거래 지역은 2-80자여야 합니다.")
    if not validate_image_url(image_url):
        errors.append("이미지 URL은 http 또는 https 주소만 허용됩니다.")
    if errors:
        raise ValueError(" ".join(errors))
    return {
        "title": title,
        "description": description,
        "category": category,
        "condition": condition,
        "price": price,
        "location": location,
        "image_url": image_url,
    }


def product_form_html(csrf: str, action: str, product) -> str:
    p = product or {}
    categories = "".join(f'<option value="{c}" {"selected" if row_get(p, "category") == c else ""}>{category_label(c)}</option>' for c in CATEGORIES)
    conditions = "".join(f'<option value="{c}" {"selected" if row_get(p, "condition") == c else ""}>{condition_label(c)}</option>' for c in CONDITIONS)
    return f"""
    <section class="panel">
      <h1>{'상품 수정' if product else '판매 상품 등록'}</h1>
      <form method="post" action="{esc(action)}" class="product-form">
        {csrf}
        <label>상품명<input name="title" maxlength="80" value="{esc(row_get(p, 'title'))}" required></label>
        <label>가격<input name="price" type="number" min="100" max="100000000" value="{esc(row_get(p, 'price'))}" required></label>
        <label>카테고리<select name="category" required>{categories}</select></label>
        <label>상품 상태<select name="condition" required>{conditions}</select></label>
        <label>거래 지역<input name="location" maxlength="80" value="{esc(row_get(p, 'location'))}" required></label>
        <label>이미지 URL<input name="image_url" maxlength="400" value="{esc(row_get(p, 'image_url'))}" placeholder="https://..."></label>
        <label class="wide">설명<textarea name="description" maxlength="1500" required>{esc(row_get(p, 'description'))}</textarea></label>
        <button>저장</button>
      </form>
    </section>
    """


def get_product_or_404(pid: int):
    with db() as con:
        product = con.execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    if not product:
        raise ValueError("상품을 찾을 수 없습니다.")
    return product


def status_options(selected: str) -> str:
    return "".join(f'<option value="{s}" {"selected" if s == selected else ""}>{status_label(s)}</option>' for s in STATUSES)


def cart_row(row, csrf: str) -> str:
    return f"""
    <article class="cart-row">
      <a href="/products/{row['id']}">{esc(row['title'])}</a>
      <span>{status_label(row['status'])}</span>
      <strong>{money(row['price'])}</strong>
      <form method="post" action="/cart/remove">{csrf}<input type="hidden" name="product_id" value="{row['id']}"><button>삭제</button></form>
    </article>
    """


def alerts(errors) -> str:
    return "".join(f"<div class='alert'>{esc(e)}</div>" for e in errors)


def log(con, user_id, action, target):
    con.execute("INSERT INTO audit_logs(user_id, action, target, created_at) VALUES (?, ?, ?, ?)", (user_id, action, target, now()))


def category_label(value: str) -> str:
    return {
        "digital": "디지털",
        "fashion": "패션",
        "home": "생활/가구",
        "book": "도서",
        "sports": "스포츠",
        "etc": "기타",
    }.get(value, value)


def condition_label(value: str) -> str:
    return {
        "new": "새상품",
        "like-new": "거의 새것",
        "good": "사용감 적음",
        "fair": "사용감 있음",
    }.get(value, value)


def status_label(value: str) -> str:
    return {
        "selling": "판매중",
        "reserved": "예약중",
        "sold": "판매완료",
    }.get(value, value)


def main():
    init_db()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), App)
    print(f"Tiny Second-hand Shopping Platform running on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()

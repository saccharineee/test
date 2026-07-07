import os
import secrets
import time
from collections import defaultdict
from datetime import timedelta, datetime
import sqlite3
import bcrypt
from flask import Flask, render_template, request, redirect, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    SESSION_REFRESH_EACH_REQUEST=True,
)
app.debug = False

# ==================== 隐藏 Server 头 ====================
class ServerHeaderMiddleware:
    def __init__(self, app):
        self.app = app
    def __call__(self, environ, start_response):
        is_logout = (environ.get("PATH_INFO", "") == "/logout")
        def custom_start_response(status, headers, exc_info=None):
            saw_server = False
            new_headers = []
            for k, v in headers:
                if k.lower() == "server":
                    if not saw_server:
                        new_headers.append((k, "Kangle/3.1"))
                        saw_server = True
                else:
                    new_headers.append((k, v))
            if not saw_server:
                new_headers.append(("Server", "Kangle/3.1"))
            if is_logout:
                new_headers.append(("Set-Cookie",
                    "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"))
            return start_response(status, new_headers, exc_info)
        return self.app(environ, custom_start_response)

app.wsgi_app = ServerHeaderMiddleware(app.wsgi_app)

import werkzeug.serving as _ws_serving
if hasattr(_ws_serving, 'WSGIRequestHandler'):
    _ws_serving.WSGIRequestHandler.server_version = "Kangle/3.1"
    _ws_serving.WSGIRequestHandler.sys_version = ""

# ==================== 数据库（安全路径） ====================
_DB_DIRS = ["/var/lib/user-manager", os.path.dirname(os.path.abspath(__file__))]
for _d in _DB_DIRS:
    try:
        os.makedirs(_d, mode=0o750, exist_ok=True)
        _db_path = os.path.join(_d, "users.db")
        open(_db_path, "a").close()
        DB_PATH = _db_path
        break
    except (OSError, PermissionError):
        continue
else:
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

if os.path.exists(DB_PATH):
    os.chmod(DB_PATH, 0o600)

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            balance INTEGER DEFAULT 0,
            login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        db.execute("INSERT INTO users (username, password_hash, role, email, phone, balance) VALUES (?,?,?,?,?,?)",
            ("admin", bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode(), "admin", "admin@example.com", "13800138000", 99999))
        db.execute("INSERT INTO users (username, password_hash, role, email, phone, balance) VALUES (?,?,?,?,?,?)",
            ("alice", bcrypt.hashpw(b"alice2025", bcrypt.gensalt()).decode(), "user", "alice@example.com", "13900139001", 100))
    db.commit()
    db.close()

def get_user(username):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    db.close()
    return dict(user) if user else None

init_db()

# ==================== 限速 + 账户锁定 ====================
LOGIN_RATE_LIMIT = 20
LOGIN_RATE_WINDOW = timedelta(minutes=15)
LOGIN_LOCK_THRESHOLD = 5
LOGIN_LOCK_DURATION = timedelta(minutes=30)
login_attempts = defaultdict(list)
fake_user_attempts = defaultdict(int)

# ==================== 辅助函数 ====================

def session_regenerate():
    for key in list(session.keys()):
        del session[key]
    session["_csrf_token"] = secrets.token_hex(32)
    session["_session_id"] = secrets.token_hex(16)
    session.permanent = True

# ==================== 路由 ====================

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    is_default_pwd = False
    if username:
        user = get_user(username)
        if user:
            user_info = {
                "username": user["username"],
                "password": "*** 已加密 ***",
                "email": user["email"],
                "phone": user["phone"],
                "role": user["role"],
                "balance": user["balance"],
            }
            if bcrypt.checkpw(b"admin123", user["password_hash"].encode()):
                is_default_pwd = True
            elif bcrypt.checkpw(b"alice2025", user["password_hash"].encode()):
                is_default_pwd = True
    return render_template("index.html", username=username, user=user_info, show_pwd_warning=is_default_pwd)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)

    if request.method == "POST":
        stored_token = session.get("_csrf_token", "")
        form_token = request.form.get("_csrf_token", "")
        if not stored_token or not secrets.compare_digest(stored_token, form_token):
            error = "表单验证失败，请重试"
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if not username or not password:
                error = "用户名或密码错误"
            else:
                client_ip = request.remote_addr or "unknown"
                now = datetime.now()
                login_attempts[client_ip] = [
                    t for t in login_attempts[client_ip]
                    if now - t < LOGIN_RATE_WINDOW
                ]
                if len(login_attempts[client_ip]) >= LOGIN_RATE_LIMIT:
                    error = "登录尝试过于频繁，请15分钟后再试"
                else:
                    login_attempts[client_ip].append(now)
                    user = get_user(username)

                    if user and user.get("locked_until"):
                        try:
                            lock_expires = datetime.fromisoformat(user["locked_until"])
                            if now < lock_expires:
                                error = "账户已被临时锁定，请30分钟后再试"
                            else:
                                db = get_db()
                                db.execute("UPDATE users SET login_attempts=0, locked_until=NULL WHERE username=?", (username,))
                                db.commit()
                                db.close()
                        except (ValueError, TypeError):
                            pass

                    if error:
                        pass
                    elif user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
                        session_regenerate()
                        session["username"] = username
                        fake_user_attempts.pop(username, None)

                        db = get_db()
                        db.execute("UPDATE users SET login_attempts=0, locked_until=NULL WHERE username=?", (username,))
                        db.commit()
                        db.close()

                        user_info = {
                            "username": user["username"],
                            "password": "*** 已加密 ***",
                            "email": user["email"],
                            "phone": user["phone"],
                            "role": user["role"],
                            "balance": user["balance"],
                        }
                        return render_template("index.html", username=username, user=user_info, show_pwd_warning=True)
                    else:
                        error = "用户名或密码错误"
                        if user:
                            db = get_db()
                            db.execute("UPDATE users SET login_attempts = login_attempts + 1 WHERE username=?", (username,))
                            attempt_count = db.execute("SELECT login_attempts FROM users WHERE username=?", (username,)).fetchone()[0]
                            if attempt_count >= LOGIN_LOCK_THRESHOLD:
                                lock_expires = (now + LOGIN_LOCK_DURATION).isoformat()
                                db.execute("UPDATE users SET locked_until=? WHERE username=?", (lock_expires, username))
                            db.commit()
                            db.close()
                        else:
                            fake_user_attempts[username] += 1
                            if fake_user_attempts[username] >= LOGIN_LOCK_THRESHOLD:
                                fake_user_attempts[username] = -((now + LOGIN_LOCK_DURATION).timestamp())

    return render_template(
        "login.html",
        error=error,
        csrf_token=session.get("_csrf_token", ""),
    )


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    username = session.get("username")
    if not username:
        return redirect("/login")

    error = None
    success = None

    if request.method == "POST":
        stored_token = session.get("_csrf_token", "")
        form_token = request.form.get("_csrf_token", "")
        if not stored_token or not secrets.compare_digest(stored_token, form_token):
            error = "表单验证失败，请重试"
        else:
            old_pw = request.form.get("old_password", "")
            new_pw = request.form.get("new_password", "")
            confirm_pw = request.form.get("confirm_password", "")

            if not old_pw or not new_pw or not confirm_pw:
                error = "请填写所有字段"
            elif new_pw != confirm_pw:
                error = "两次输入的新密码不一致"
            elif len(new_pw) < 8:
                error = "新密码长度至少 8 位"
            else:
                user = get_user(username)
                if user and bcrypt.checkpw(old_pw.encode(), user["password_hash"].encode()):
                    new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
                    db = get_db()
                    db.execute("UPDATE users SET password_hash=? WHERE username=?", (new_hash, username))
                    db.commit()
                    db.close()
                    success = "密码修改成功"
                else:
                    error = "旧密码错误"

    return render_template(
        "change_password.html",
        error=error,
        success=success,
        csrf_token=session.get("_csrf_token", ""),
    )


@app.route("/logout")
def logout():
    session.clear()
    session.modified = True
    resp = redirect("/")
    return resp


if __name__ == "__main__":
    import warnings
    warnings.warn(
        "当前使用 Flask 开发服务器，仅适用于开发/演示。"
        "生产部署请使用 Gunicorn + uWSGI 等 WSGI 服务器。"
    )
    app.run(debug=False, host="0.0.0.0", port=5000)

import os
import secrets
import json
import time
import re
from collections import defaultdict
from datetime import timedelta, datetime
import sqlite3
import bcrypt
import werkzeug.utils
from flask import (
    Flask, render_template, request, redirect, session, url_for, send_from_directory, abort
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    SESSION_REFRESH_EACH_REQUEST=True,
)
app.debug = False

# ==================== 安全响应头中间件 ====================
class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app
    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            def set_header(key, value):
                key_lower = key.lower()
                for i, (k, v) in enumerate(headers):
                    if k.lower() == key_lower:
                        headers[i] = (key, value)
                        return
                headers.append((key, value))
            set_header("X-Frame-Options", "DENY")
            set_header("X-Content-Type-Options", "nosniff")
            set_header("X-XSS-Protection", "0")
            set_header("Referrer-Policy", "strict-origin-when-cross-origin")
            set_header("Content-Security-Policy",
                "default-src 'self'; "
                "img-src 'self' data:; "
                "style-src 'self'; "
                "script-src 'self'; "
                "base-uri 'self'; "
                "form-action 'self'")
            return start_response(status, headers, exc_info)
        return self.app(environ, custom_start_response)

app.wsgi_app = SecurityHeadersMiddleware(app.wsgi_app)

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

# ==================== 数据库 ====================
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
    db.execute("PRAGMA foreign_keys=ON")
    return db

# ==================== 速率限制持久化 ====================
RATE_LIMIT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(RATE_LIMIT_DIR, exist_ok=True)
RATE_STATE_PATH = os.path.join(RATE_LIMIT_DIR, "rate_state.json")
LOGIN_RATE_LIMIT = 20
LOGIN_RATE_WINDOW = timedelta(minutes=15)
LOGIN_LOCK_THRESHOLD = 5
LOGIN_LOCK_DURATION = timedelta(minutes=30)

def _load_rate_state():
    try:
        if os.path.exists(RATE_STATE_PATH):
            with open(RATE_STATE_PATH, "r") as f:
                data = json.load(f)
            return data.get("login_attempts", {}), data.get("fake_user_attempts", {})
    except (json.JSONDecodeError, OSError):
        pass
    return {}, {}

def _save_rate_state(login_data, fake_data):
    try:
        with open(RATE_STATE_PATH, "w") as f:
            json.dump({
                "login_attempts": login_data,
                "fake_user_attempts": fake_data,
                "updated_at": datetime.now().isoformat(),
            }, f)
    except OSError:
        pass

def _prune_rate_state(login_data, fake_data):
    now = datetime.now()
    cutoff = (now - LOGIN_RATE_WINDOW).timestamp()
    pruned_login = {}
    for ip, timestamps in login_data.items():
        valid = [t for t in timestamps if t >= cutoff]
        if valid:
            pruned_login[ip] = valid
    pruned_fake = {}
    for user, val in fake_data.items():
        if isinstance(val, (int, float)):
            if val > 0:
                pruned_fake[user] = val
            elif val < 0:
                lock_exp = datetime.fromtimestamp(-val)
                if now < lock_exp:
                    pruned_fake[user] = val
    return pruned_login, pruned_fake

def check_rate_limit(ip):
    login_data, fake_data = _load_rate_state()
    now = datetime.now()
    now_ts = time.time()
    cutoff_ts = (now - LOGIN_RATE_WINDOW).timestamp()
    ip_timestamps = login_data.get(ip, [])
    ip_timestamps = [t for t in ip_timestamps if t >= cutoff_ts]
    if len(ip_timestamps) >= LOGIN_RATE_LIMIT:
        return False, "登录尝试过于频繁，请15分钟后再试"
    ip_timestamps.append(now_ts)
    login_data[ip] = ip_timestamps
    login_data, fake_data = _prune_rate_state(login_data, fake_data)
    _save_rate_state(login_data, fake_data)
    return True, None

def record_fake_attempt(username):
    login_data, fake_data = _load_rate_state()
    val = fake_data.get(username, 0)
    if isinstance(val, (int, float)) and val >= 0:
        val = int(val) + 1
        if val >= LOGIN_LOCK_THRESHOLD:
            now = datetime.now()
            lock_exp = now + LOGIN_LOCK_DURATION
            val = -lock_exp.timestamp()
        fake_data[username] = val
    login_data, fake_data = _prune_rate_state(login_data, fake_data)
    _save_rate_state(login_data, fake_data)

def is_fake_user_locked(username):
    login_data, fake_data = _load_rate_state()
    val = fake_data.get(username)
    if val is None:
        return False
    if isinstance(val, (int, float)) and val < 0:
        now = datetime.now()
        lock_exp = datetime.fromtimestamp(-val)
        if now < lock_exp:
            return True
    return False

# ==================== 数据库初始化 ====================
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
    # 为已有表添加 password_changed_at 列（幂等）
    try:
        db.execute("ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP DEFAULT NULL")
    except sqlite3.OperationalError:
        pass
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


def get_user_by_id(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    db.close()
    return dict(user) if user else None

def _sanitize_username(username):
    """仅允许字母、数字、中文、下划线、连字符，过滤特殊字符"""
    sanitized = re.sub(r'[^\w\u4e00-\u9fff\-]', '', username)
    return sanitized.strip()[:32]


def create_user(username, password_hash, email, phone):
    db = get_db()
    try:
        # 对用户名进行过滤，防止SQL注入字符和XSS payload入库
        clean_username = _sanitize_username(username)
        if not clean_username or len(clean_username) < 2:
            return False, "用户名包含非法字符，请使用字母、数字、中文或下划线"
        db.execute(
            "INSERT INTO users (username, password_hash, email, phone) VALUES (?, ?, ?, ?)",
            (clean_username, password_hash, email, phone),
        )
        db.commit()
        return True, None
    except sqlite3.IntegrityError:
        return False, "用户名已存在"
    except Exception as e:
        return False, f"注册失败：{e}"
    finally:
        db.close()

def _mask_phone(phone):
    """手机号脱敏：13800138000 -> 138****8000"""
    if phone and len(phone) >= 7:
        return phone[:3] + "****" + phone[-4:]
    return phone or ""


def _mask_email(email):
    """邮箱脱敏：admin@example.com -> a***@example.com"""
    if email and "@" in email:
        local, domain = email.split("@", 1)
        if len(local) >= 2:
            return local[0] + "***@" + domain
        return local[0] + "***@" + domain
    return email or ""


def _check_default_password(user):
    """检查用户是否还在使用初始默认密码"""
    if user and user.get("password_hash"):
        for default_pwd in [b"admin123", b"alice2025"]:
            if bcrypt.checkpw(default_pwd, user["password_hash"].encode()):
                return True
    return False


def search_users(keyword):
    db = get_db()
    try:
        like_pattern = f"%{keyword}%"
        rows = db.execute(
            "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
            (like_pattern, like_pattern),
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["email"] = _mask_email(d.get("email", ""))
            d["phone"] = _mask_phone(d.get("phone", ""))
            results.append(d)
        return results
    finally:
        db.close()

init_db()

# ==================== Session 密码变更校验 ====================
def _get_password_changed_at(username):
    db = get_db()
    try:
        row = db.execute("SELECT password_changed_at FROM users WHERE username=?", (username,)).fetchone()
        if row and row["password_changed_at"]:
            return datetime.fromisoformat(row["password_changed_at"]).timestamp()
    except (ValueError, TypeError, AttributeError):
        pass
    finally:
        db.close()
    return None

def invalidate_session_after_password_change():
    username = session.get("username")
    login_time = session.get("_login_time")
    if username and login_time:
        changed_at = _get_password_changed_at(username)
        if changed_at and login_time < changed_at:
            session.clear()
            session.modified = True

app.before_request(invalidate_session_after_password_change)

# ==================== 上传配置 ====================
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 安全的文件扩展名白名单（不含SVG——SVG可嵌入JS导致存储型XSS）
ALLOWED_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "bmp", "webp",
    "ico", "tiff", "tif",
}

# 文件魔数签名校验 (magic bytes)
FILE_MAGIC_SIGNATURES = {
    b"\xff\xd8\xff":           {"jpg", "jpeg"},
    b"\x89PNG\r\n\x1a\n":       {"png"},
    b"GIF87a":                  {"gif"},
    b"GIF89a":                  {"gif"},
    b"BM":                      {"bmp"},
    b"RIFF":                    {"webp"},  # WEBP 以 RIFF 开头
    b"\x00\x00\x01\x00":         {"ico"},
    b"MM\x00*":                  {"tiff", "tif"},
    b"II*\x00":                  {"tiff", "tif"},
}

# 最小文件大小（字节），防止空文件
MIN_FILE_SIZE = 100

# 每个用户头像数量限制
MAX_FILES_PER_USER = 5


def _safe_filename(filename):
    """防止路径穿越 + 只允许安全的扩展名"""
    if not filename or filename == ".":
        return None
    # 路径穿越防护
    safe = werkzeug.utils.secure_filename(filename)
    if not safe:
        return None
    # 扩展名白名单检查
    ext = safe.rsplit(".", 1)[-1].lower() if "." in safe else ""
    if ext not in ALLOWED_EXTENSIONS:
        return None
    return safe


def _check_file_magic(file_data, extension):
    """校验文件魔数是否匹配声明的扩展名"""
    for magic, exts in FILE_MAGIC_SIGNATURES.items():
        if file_data[:len(magic)] == magic:
            return extension in exts
    return False


def _sanitize_svg(filepath):
    """此函数不再使用——SVG已被从白名单移除"""
    pass


def _random_filename(original_ext):
    """生成随机UUID文件名，防止文件名枚举和冲突"""
    random_name = secrets.token_hex(16)
    return f"{random_name}.{original_ext}"

# ==================== 辅助函数 ====================

def session_regenerate():
    """登录后完全重建session，防会话固定"""
    for key in list(session.keys()):
        del session[key]
    session["_csrf_token"] = secrets.token_hex(32)
    session["_session_id"] = secrets.token_hex(16)
    session["_login_time"] = time.time()
    session.permanent = True

# ==================== 个人中心和充值 ====================

@app.route("/profile")
def profile():
    username = session.get("username")
    if not username:
        return redirect("/login")

    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)

    # 强制显示当前登录用户的资料，忽略 URL 中的 user_id
    current_user = get_user(username)
    if not current_user:
        return redirect("/login")
    display_user = dict(current_user)
    display_user["email"] = _mask_email(current_user.get("email", ""))
    display_user["phone"] = _mask_phone(current_user.get("phone", ""))
    return render_template("profile.html", user=display_user, error=None,
        csrf_token=session.get("_csrf_token", ""))


@app.route("/recharge", methods=["POST"])
def recharge():
    username = session.get("username")
    if not username:
        return redirect("/login")

    # CSRF 校验
    stored_token = session.get("_csrf_token", "")
    form_token = request.form.get("_csrf_token", "")
    if not stored_token or not secrets.compare_digest(stored_token, form_token):
        user_id_param = request.form.get("user_id", type=int)
        return redirect(f"/profile?user_id={user_id_param or ''}")

    amount = request.form.get("amount", type=int, default=0)

    # 强制使用当前登录用户的 ID，防止篡改表单中的 user_id 给他人充值
    current_user = get_user(username)
    if not current_user:
        return redirect("/login")
    user_id = current_user["id"]

    if amount < 0:
        display_user = dict(current_user)
        display_user["email"] = _mask_email(current_user.get("email", ""))
        display_user["phone"] = _mask_phone(current_user.get("phone", ""))
        return render_template("profile.html", user=display_user,
            error="充值金额不能为负数",
            csrf_token=session.get("_csrf_token", ""))

    new_balance = current_user["balance"] + amount
    db = get_db()
    db.execute("UPDATE users SET balance=? WHERE id=?", (new_balance, user_id))
    db.commit()
    db.close()
    return redirect(f"/profile?user_id={user_id}")


# ==================== 模板上下文注入 ====================

@app.context_processor
def inject_user_profile():
    """向所有模板注入当前登录用户的 user_id（如果有）"""
    username = session.get("username")
    if username:
        user = get_user(username)
        if user:
            return {"logged_in_user_id": user["id"]}
    return {"logged_in_user_id": None}


# ==================== 动态页面加载 ====================

@app.route("/page")
def page():
    name = request.args.get("name", "")
    page_content = None

    if not name:
        page_content = "请输入页面名称"
    else:
        # 路径穿越防护：解析为绝对路径并验证是否在 pages/ 目录下
        pages_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
        # 对 name 做基本过滤：只允许字母、数字、下划线、连字符、点
        safe_name = re.sub(r'[^\w\-. ]', '', name)
        # 防止路径穿越：用 abspath 归一化后检查前缀
        filepath = os.path.join(pages_dir, safe_name)
        filepath = os.path.abspath(filepath)
        if not filepath.startswith(os.path.abspath(pages_dir) + os.sep):
            page_content = "页面不存在"
        elif os.path.isfile(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                page_content = f.read()
        else:
            filepath_html = filepath + ".html"
            if os.path.isfile(filepath_html):
                with open(filepath_html, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                page_content = "页面不存在"

    username = session.get("username")
    user_info = None
    is_default_pwd = False
    if username:
        user = get_user(username)
        if user:
            is_default_pwd = _check_default_password(user)
            user_info = {
                "id": user["id"],
                "username": user["username"],
                "email": _mask_email(user.get("email", "")),
                "phone": _mask_phone(user.get("phone", "")),
                "role": user["role"],
                "balance": user["balance"],
            }
    return render_template("index.html", username=username, user=user_info,
        page_content=page_content)


# ==================== 路由 ====================

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    is_default_pwd = False
    if username:
        user = get_user(username)
        if user:
            is_default_pwd = _check_default_password(user)
            user_info = {
                "id": user["id"],
                "username": user["username"],
                "email": _mask_email(user.get("email", "")),
                "phone": _mask_phone(user.get("phone", "")),
                "role": user["role"],
                "balance": user["balance"],
            }
    return render_template("index.html", username=username, user=user_info)


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
            # 登录后刷新 CSRF token，防重放
            session["_csrf_token"] = secrets.token_hex(32)

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if not username or not password:
                error = "用户名或密码错误"
            else:
                client_ip = request.remote_addr or "unknown"
                now = datetime.now()

                if is_fake_user_locked(username):
                    error = "账户已被临时锁定，请30分钟后再试"

                if not error:
                    allowed, rate_error = check_rate_limit(client_ip)
                    if not allowed:
                        error = rate_error

                if not error:
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

                        db = get_db()
                        db.execute("UPDATE users SET login_attempts=0, locked_until=NULL WHERE username=?", (username,))
                        db.commit()
                        db.close()

                        user_info = {
                            "id": user["id"],
                            "username": user["username"],
                            "email": _mask_email(user.get("email", "")),
                            "phone": _mask_phone(user.get("phone", "")),
                            "role": user["role"],
                            "balance": user["balance"],
                        }
                        return render_template("index.html", username=username, user=user_info)
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
                            record_fake_attempt(username)

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

    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)

    if request.method == "GET":
        return render_template("change_password.html",
            username=username,
            error=request.args.get("error", ""),
            success=request.args.get("success", ""),
            csrf_token=session.get("_csrf_token", ""))

    # CSRF 校验
    stored_token = session.get("_csrf_token", "")
    form_token = request.form.get("_csrf_token", "")
    if not stored_token or not secrets.compare_digest(stored_token, form_token):
        return render_template("change_password.html",
            username=username,
            error="表单验证失败，请重试",
            success="",
            csrf_token=session.get("_csrf_token", ""))

    session["_csrf_token"] = secrets.token_hex(32)

    new_pw = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")

    if not new_pw or not confirm_pw:
        return render_template("change_password.html",
            username=username, error="请填写所有字段", success="",
            csrf_token=session.get("_csrf_token", ""))
    
    if new_pw != confirm_pw:
        return render_template("change_password.html",
            username=username, error="两次输入的新密码不一致", success="",
            csrf_token=session.get("_csrf_token", ""))
    
    if len(new_pw) < 8:
        return render_template("change_password.html",
            username=username, error="新密码长度至少 8 位", success="",
            csrf_token=session.get("_csrf_token", ""))
    
    if len(new_pw) > 128:
        return render_template("change_password.html",
            username=username, error="新密码过长", success="",
            csrf_token=session.get("_csrf_token", ""))

    new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    db.execute("UPDATE users SET password_hash=?, password_changed_at=? WHERE username=?",
        (new_hash, datetime.now().isoformat(), username))
    db.commit()
    db.close()

    return render_template("change_password.html",
        username=username,
        error="",
        success="密码修改成功",
        csrf_token=session.get("_csrf_token", ""))


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None

    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)

    if request.method == "POST":
        stored_token = session.get("_csrf_token", "")
        form_token = request.form.get("_csrf_token", "")
        if not stored_token or not secrets.compare_digest(stored_token, form_token):
            error = "表单验证失败，请重试"
        else:
            session["_csrf_token"] = secrets.token_hex(32)

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()

            if not username or not password:
                error = "用户名和密码不能为空"
            elif len(password) < 8:
                error = "密码长度至少 8 位"
            elif len(password) > 128:
                error = "密码过长"
            elif len(username) > 32:
                error = "用户名过长"
            elif len(email) > 64:
                error = "邮箱地址过长"
            elif len(phone) > 20:
                error = "手机号过长"
            else:
                password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                ok, msg = create_user(username, password_hash, email, phone)
                if ok:
                    success = True
                else:
                    error = msg
    return render_template("register.html", error=error, success=success,
        csrf_token=session.get("_csrf_token", ""))


@app.route("/search")
def search():
    username = session.get("username")
    if not username:
        return redirect("/login")

    keyword = request.args.get("keyword", "").strip()
    results = []
    if keyword:
        results = search_users(keyword)
    return render_template("search.html", results=results, keyword=keyword)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    username = session.get("username")
    if not username:
        return redirect("/login")

    error = None
    uploaded_url = None

    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)

    if request.method == "POST":
        stored_token = session.get("_csrf_token", "")
        form_token = request.form.get("_csrf_token", "")
        if not stored_token or not secrets.compare_digest(stored_token, form_token):
            error = "表单验证失败，请重试"
            return render_template("upload.html", error=error, uploaded_url=None,
                csrf_token=session.get("_csrf_token", ""))

        session["_csrf_token"] = secrets.token_hex(32)

        file = request.files.get("file")
        if not file or file.filename == "":
            error = "请选择要上传的文件"
        else:
            filename = _safe_filename(file.filename)
            if filename is None:
                error = "不支持的文件类型，仅允许图片文件（jpg/png/gif/bmp/webp/ico/tiff）"
                return render_template("upload.html", error=error, uploaded_url=None,
                    csrf_token=session.get("_csrf_token", ""))

            ext = filename.rsplit(".", 1)[-1].lower()

            # 读取文件头做魔数校验
            file.seek(0)
            file_data = file.read(16)
            file.seek(0)

            if not _check_file_magic(file_data, ext):
                error = "文件内容与扩展名不匹配，请上传真实的图片文件"
                return render_template("upload.html", error=error, uploaded_url=None,
                    csrf_token=session.get("_csrf_token", ""))

            # 检查文件最小大小
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)

            if file_size < MIN_FILE_SIZE:
                error = f"文件太小（{file_size} 字节），至少需要 {MIN_FILE_SIZE} 字节"
                return render_template("upload.html", error=error, uploaded_url=None,
                    csrf_token=session.get("_csrf_token", ""))

            # 使用随机文件名
            safe_name = _random_filename(ext)
            save_path = os.path.join(UPLOAD_FOLDER, safe_name)

            # 如果文件名冲突则重试
            retries = 0
            while os.path.exists(save_path) and retries < 10:
                safe_name = _random_filename(ext)
                save_path = os.path.join(UPLOAD_FOLDER, safe_name)
                retries += 1

            file.save(save_path)
            # 确保上传文件权限安全
            os.chmod(save_path, 0o644)
            uploaded_url = f"/static/uploads/{safe_name}"

    return render_template("upload.html", error=error, uploaded_url=uploaded_url,
        csrf_token=session.get("_csrf_token", ""))


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

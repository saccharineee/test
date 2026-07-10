# Flask 用户管理系统

一个基于 Flask 框架的用户管理 Web 应用，经过全面安全加固，包含个人中心与余额充值功能。

## 技术栈

- **后端**: Python 3.13 + Flask 3.x
- **数据库**: SQLite（WAL 模式）
- **密码哈希**: bcrypt（随机盐）
- **前端**: Jinja2 模板 + CSS

## 功能

- 用户注册 / 登录 / 登出
- 用户信息展示（个人中心）
- 密码修改（最小 8 位 + 旧密码验证）
- 余额充值（登录保护 + CSRF 防护）
- 用户搜索（参数化查询，结果脱敏）
- 文件上传（魔数校验 + 随机文件名）
- 弱密码检测提示

## 安全特性

| 类别 | 防护措施 |
|------|---------|
| 认证安全 | bcrypt 密码哈希 + 随机盐 |
| 会话安全 | HttpOnly + SameSite=Lax + 2h 超时 + 会话固定防御 |
| 暴力破解防护 | 每 IP 15 分钟 20 次限速 + 5 次失败锁定 30 分钟 |
| CSRF 防护 | Session 绑定 Token + secrets.compare_digest |
| 越权防护 | 强制使用 session 用户身份，忽略客户端传入的 user_id |
| 参数校验 | 禁止负数充值 |
| 数据脱敏 | 邮箱 / 手机号脱敏展示 |
| 信息隐藏 | Server 头伪装 Kangle/3.1 + 统一登录错误信息 |
| 防用户枚举 | 统一错误响应 + 一致响应长度 + 虚假账户锁定 |
| 密钥安全 | 启动时随机生成 64 位十六进制密钥 |
| 生产提示 | 启动时警告使用 Gunicorn 替代开发服务器 |
| 文件上传 | 魔数校验（PNG/JPEG/GIF）+ 随机文件名 + 大小限制 |

## 快速启动

```bash
# 安装依赖
pip install flask bcrypt

# 运行
python app.py
```

默认监听 `0.0.0.0:5000`。

## 测试凭据

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | admin123 | 管理员 |
| alice | alice2025 | 普通用户 |

⚠️ 首次登录后建议立即修改默认密码。

## 项目结构

```
user-manager/
├── app.py                     # 主程序
├── templates/
│   ├── base.html              # 基础模板
│   ├── login.html             # 登录页
│   ├── register.html          # 注册页
│   ├── index.html             # 首页
│   ├── profile.html           # 个人中心
│   ├── change_password.html   # 修改密码
│   ├── search.html            # 用户搜索
│   └── upload.html            # 文件上传
├── static/css/
│   └── style.css              # 样式文件
├── .gitignore
└── README.md
```

## 安全验证

项目通过了多项安全指标验证，覆盖：
- Server 头信息隐藏
- Cookie 安全属性设置
- 会话固定防御
- 密码强度检测
- CSRF 防护
- 用户枚举防护
- 账户锁定机制
- 速率限制
- 越权访问防护
- 参数篡改防护
- 文件上传安全

## 生产部署建议

- 使用 **Gunicorn + Nginx** 反向代理替代 Flask 开发服务器
- 启用 **HTTPS**（设置 `SESSION_COOKIE_SECURE=True`）
- 持久化速率计数（推荐 Redis）
- 配置 WAF / IDS 入侵检测

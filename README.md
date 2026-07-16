# 用户管理系统

基于 Flask 的用户管理 Web 应用，支持用户注册、登录、密码修改、充值、头像上传、用户搜索、URL 抓取、Ping 网络诊断等功能。

## 快速启动

```bash
pip install flask bcrypt
python app.py
```

访问 http://localhost:5000

## 默认账户

- 用户名: `admin`
- 密码: `admin123`

## 功能

- 用户注册/登录/退出
- 个人中心 & 余额充值
- 上传头像（图片类型/魔数校验）
- 用户搜索
- 动态页面加载
- URL 内容抓取（SSRF 防护）
- Ping 网络诊断（命令注入防护）

## 安全

- CSRF token 防护
- Session 超时 & 安全 Cookie
- 密码 bcrypt 哈希
- 登录速率限制 & 账户锁定
- 文件类型 & 魔数双重校验
- SSRF / 命令注入 / XSS 防护

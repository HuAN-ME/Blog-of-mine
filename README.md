# Blog-of-mine

极简个人博客 — 单文件后端 + 静态前端，支持图片文章、评论、时间轴、标签筛选、管理后台。

## 功能

- 瀑布流文章卡片，带图片轮播
- 文章详情弹窗，代码语法高亮（highlight.js）
- 标签云筛选 + 标签分组浏览
- 时间轴页面
- 站内评论
- 访问统计
- 管理后台：发布/编辑文章、站点配置、图片上传、清除未引用图片
- 暗色主题，响应式适配（手机/PC）
- MySQL 账号体系 + JWT 鉴权

## 技术栈

- **后端**: Node.js + Express 5
- **数据库**: MySQL 8
- **认证**: JWT (httpOnly cookie)
- **前端**: 原生 HTML/CSS/JS，无框架依赖
- **代码高亮**: highlight.js (CDN)
- **安全**: helmet, sanitize-html, rate-limit

## 部署

### 环境要求

- Node.js >= 16
- MySQL 8.0

### 1. 克隆仓库

```bash
git clone https://github.com/HuAN-ME/Blog-of-mine.git
cd Blog-of-mine
```

### 2. 安装依赖

```bash
npm install
```

### 3. 创建 `.env` 文件

```bash
cp .env.example .env
```

编辑 `.env`，填入实际值：

```env
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=<你的MySQL密码>
MYSQL_DATABASE=blog

JWT_SECRET=<生成一段64位随机字符串>

INIT_ADMIN_PASSWORD=<首次启动时admin的初始密码>

# 以下为可选（邮箱验证用）
SMTP_HOST=smtp.qq.com
SMTP_PORT=465
SMTP_USER=<你的QQ邮箱>
SMTP_PASS=<QQ邮箱SMTP授权码>
```

生成 `JWT_SECRET`：

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"
```

### 4. 创建数据库

```sql
CREATE DATABASE blog CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 5. 启动

```bash
npm start
```

访问 `http://localhost:3000` 查看博客，`http://localhost:3000/admin.html` 进入管理后台。

### 生产环境

用 PM2 保持常驻，Nginx 反代 + SSL。

## 管理后台

登录账号为 `admin`，密码为 `INIT_ADMIN_PASSWORD` 设定的值（仅首次启动创建）。

管理后台可操作：
- 新建/编辑/删除文章（支持 Markdown 风格图片粘贴上传）
- 编辑站点配置（标题、简介、头像、背景）
- 编辑时间轴
- 上传图片
- 清除磁盘上未引用的图片

## 目录结构

```
├── server.js          # Express 后端（所有路由、中间件）
├── index.html         # 博客前端
├── admin.html         # 管理后台
├── posts/             # 文章 JSON 数据
├── images/
│   └── posts/         # 文章图片
├── config.json        # 站点配置
├── timeline.json      # 时间轴数据
├── messages.json      # 评论数据
├── visits.json        # 访问计数
└── .env.example       # 环境变量模板
```

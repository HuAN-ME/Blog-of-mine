require('dotenv').config();

const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const sanitizeHtml = require('sanitize-html');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

// ── HTML sanitization whitelists ──

const POST_SANITIZE = {
  allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'h1', 'h2', 'span', 'u', 's', 'pre', 'code']),
  allowedAttributes: {
    a: ['href', 'target', 'rel'],
    img: ['src', 'alt', 'width', 'height', 'loading'],
    code: ['class'],
    pre: ['class', 'data-lang']
  },
  allowedSchemes: ['http', 'https', 'mailto'],
  transformTags: {
    'a': (tagName, attribs) => {
      if (attribs.href && !/^(https?:)?\/\//.test(attribs.href) && !attribs.href.startsWith('mailto:')) {
        delete attribs.href;
      }
      return { tagName, attribs };
    }
  }
};

const SUBTITLE_SANITIZE = {
  allowedTags: ['strong', 'em', 'u', 's', 'a', 'br', 'span', 'code'],
  allowedAttributes: {
    a: ['href', 'target', 'rel']
  },
  allowedSchemes: ['http', 'https', 'mailto'],
  transformTags: {
    'a': (tagName, attribs) => {
      if (attribs.href && !/^(https?:)?\/\//.test(attribs.href) && !attribs.href.startsWith('mailto:')) {
        delete attribs.href;
      }
      return { tagName, attribs };
    }
  }
};

const app = express();
app.set('trust proxy', 1);
app.use(cookieParser());
const PORT = process.env.PORT || 3000;
const POSTS_DIR = path.join(__dirname, 'posts');
const CONFIG_PATH = path.join(__dirname, 'config.json');
const TIMELINE_PATH = path.join(__dirname, 'timeline.json');
const VISITS_FILE = path.join(__dirname, 'visits.json');
const MESSAGES_FILE = path.join(__dirname, 'messages.json');

// Visits tracking
let visits = {};
if (fs.existsSync(VISITS_FILE)) {
  try { visits = JSON.parse(fs.readFileSync(VISITS_FILE, 'utf8')); } catch {}
}
function saveVisits() {
  fs.writeFileSync(VISITS_FILE, JSON.stringify(visits), 'utf8');
}

// MySQL connection pool
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || 'localhost',
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DATABASE || 'blog',
  waitForConnections: true,
  connectionLimit: 10
});

// Mail transporter (lazy init)
let mailer = null;
function getMailer() {
  if (mailer) return mailer;
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    const port = parseInt(process.env.SMTP_PORT) || 465;
    mailer = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port,
      secure: port === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
  }
  return mailer;
}

// JWT config
const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_TTL = '2h';
const TOKEN_TTL_MS = 2 * 60 * 60 * 1000;
const TOKEN_REFRESH = 60 * 60 * 1000; // refresh if < 1h remaining
const tokenBlacklist = new Map(); // jti -> expiresAt

// Clean expired blacklist entries every hour
setInterval(() => {
  const now = Date.now();
  for (const [jti, exp] of tokenBlacklist) {
    if (exp < now) tokenBlacklist.delete(jti);
  }
}, 3600_000);

// Verification code store (in-memory): { username -> { code, expires, lastSent } }
const codeStore = new Map();
const CODE_TTL = 5 * 60 * 1000; // 5 minutes
const CODE_COOLDOWN = 60 * 1000; // 1 minute between resends

// Rate limiters
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: '登录尝试过于频繁，请15分钟后再试' },
  standardHeaders: true,
  legacyHeaders: false,
});
const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { error: '重置请求过于频繁，请1小时后再试' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      mediaSrc: ["'self'"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
    }
  },
  frameguard: { action: 'deny' }
}));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

const codeVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: '验证尝试过于频繁，请15分钟后再试' },
  standardHeaders: true,
  legacyHeaders: false,
});

const messageLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: '留言过于频繁，请15分钟后再试' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(express.json({ limit: '200kb' }));

// Visit tracking middleware
app.use((req, res, next) => {
  if (req.method === 'GET' && (req.path === '/' || req.path === '/index.html')) {
    const today = new Date().toISOString().slice(0, 10);
    visits[today] = (visits[today] || 0) + 1;
    if (visits[today] % 10 === 0) saveVisits();
  }
  next();
});

// Block static access to sensitive files
const STATIC_BLOCKED = new Set([
  '.env', 'server.js', 'package.json', 'package-lock.json',
  'users.json', 'config.json', 'timeline.json', 'visits.json', 'messages.json',
  'query', 'node_modules', '.git', '.gitignore',
  'posts', 'scripts'
]);
app.use((req, res, next) => {
  const seg = req.path.split('/')[1];
  if (seg.startsWith('.') || STATIC_BLOCKED.has(seg)) return res.status(404).end();
  next();
});

app.use(express.static(__dirname));

// ── DB init ──

async function initDB() {
  const conn = await pool.getConnection();
  try {
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        email VARCHAR(100) UNIQUE,
        email_verified TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Migrate admin from users.json if not already in DB
    const [rows] = await conn.execute('SELECT id FROM users WHERE username = ?', ['admin']);
    if (rows.length === 0) {
      const usersPath = path.join(__dirname, 'users.json');
      if (fs.existsSync(usersPath)) {
        const usersData = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
        const admin = usersData.users.find(u => u.username === 'admin');
        if (admin) {
          await conn.execute(
            'INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)',
            [uuidv4(), 'admin', admin.passwordHash]
          );
          console.log('[DB] admin account migrated from users.json');
        }
      }
      // If no users.json and no admin, require INIT_ADMIN_PASSWORD env var
      if (!fs.existsSync(usersPath)) {
        const initPass = process.env.INIT_ADMIN_PASSWORD;
        if (!initPass) {
          console.error('[DB] 需要设置环境变量 INIT_ADMIN_PASSWORD 来创建初始管理员');
          process.exit(1);
        }
        const hash = await bcrypt.hash(initPass, 10);
        await conn.execute(
          'INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)',
          [uuidv4(), 'admin', hash]
        );
        console.log('[DB] admin account created from INIT_ADMIN_PASSWORD');
      }
    }
  } finally {
    conn.release();
  }
}

// ── Auth helpers (MySQL) ──

async function findUserByUsername(username) {
  const [rows] = await pool.execute(
    'SELECT id, username, password_hash, email, email_verified FROM users WHERE username = ?',
    [username]
  );
  return rows[0] || null;
}

async function updatePasswordHash(username, newHash) {
  await pool.execute(
    'UPDATE users SET password_hash = ? WHERE username = ?',
    [newHash, username]
  );
}

async function updateUserEmail(username, email) {
  await pool.execute(
    'UPDATE users SET email = ?, email_verified = 0 WHERE username = ?',
    [email, username]
  );
}

async function verifyUserEmail(username) {
  await pool.execute(
    'UPDATE users SET email_verified = 1 WHERE username = ?',
    [username]
  );
}

async function unbindUserEmail(username) {
  await pool.execute(
    'UPDATE users SET email = NULL, email_verified = 0 WHERE username = ?',
    [username]
  );
}

async function getUserForVerification(username) {
  const [rows] = await pool.execute(
    'SELECT username, email, email_verified FROM users WHERE username = ?',
    [username]
  );
  return rows[0] || null;
}

async function updateUserUsername(oldUsername, newUsername) {
  await pool.execute(
    'UPDATE users SET username = ? WHERE username = ?',
    [newUsername, oldUsername]
  );
}

function checkAdmin(req, res, next) {
  let token = null;
  if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  } else if (req.headers['authorization'] && req.headers['authorization'].startsWith('Bearer ')) {
    token = req.headers['authorization'].slice(7);
  }
  if (!token) return res.status(401).json({ error: '未登录' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (tokenBlacklist.has(decoded.jti)) {
      if (tokenBlacklist.get(decoded.jti) < Date.now()) {
        tokenBlacklist.delete(decoded.jti);
      } else {
        return res.status(401).json({ error: '登录已失效' });
      }
    }
    req.username = decoded.username;
    req.tokenJti = decoded.jti;
    req.tokenExp = decoded.exp;
    next();
  } catch (err) {
    return res.status(401).json({ error: '登录已过期' });
  }
}

function tokenRefresh(req, res, next) {
  if (req.username && req.tokenExp && (req.tokenExp * 1000 - Date.now()) < TOKEN_REFRESH) {
    const newJti = crypto.randomUUID();
    const newToken = jwt.sign({ username: req.username, jti: newJti }, JWT_SECRET, { expiresIn: TOKEN_TTL });
    if (req.tokenJti) tokenBlacklist.set(req.tokenJti, req.tokenExp * 1000);
    res.cookie('token', newToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: TOKEN_TTL_MS
    });
  }
  next();
}

app.use(tokenRefresh);

// ── Auth APIs ──

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '请输入账户和密码' });
  }
  try {
    const user = await findUserByUsername(username);
    if (!user) return res.status(401).json({ error: '账户或密码错误' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: '账户或密码错误' });
    const jti = crypto.randomUUID();
    const token = jwt.sign({ username, jti }, JWT_SECRET, { expiresIn: TOKEN_TTL });
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: TOKEN_TTL_MS
    });
    res.json({ token, username });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: '服务器错误' });
  }
});

app.post('/api/auth/change-password', checkAdmin, async (req, res) => {
  const { oldPassword, newPassword, code } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: '请输入新旧密码' });
  }
  if (newPassword.length < 8 || newPassword.length > 32 ||
      !/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) ||
      !/[0-9]/.test(newPassword)) {
    return res.status(400).json({ error: '密码需8-32位，包含大小写字母和数字' });
  }
  try {
    const user = await findUserByUsername(req.username);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    const match = await bcrypt.compare(oldPassword, user.password_hash);
    if (!match) return res.status(400).json({ error: '原密码错误' });

    // If email is verified, require verification code
    if (user.email_verified === 1) {
      if (!code || code.length !== 6) {
        return res.status(400).json({ error: '请先发送并输入邮箱验证码' });
      }
      const stored = codeStore.get(req.username);
      if (!stored || Date.now() > stored.expires || String(stored.code) !== String(code)) {
        codeStore.delete(req.username);
        return res.status(400).json({ error: '验证码错误或已过期' });
      }
      codeStore.delete(req.username);
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await updatePasswordHash(req.username, newHash);
    res.json({ ok: true });
  } catch (err) {
    console.error('Change-password error:', err.message);
    res.status(500).json({ error: '服务器错误' });
  }
});

app.post('/api/auth/logout', checkAdmin, (req, res) => {
  if (req.tokenJti) tokenBlacklist.set(req.tokenJti, req.tokenExp * 1000);
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/auth/me', checkAdmin, async (req, res) => {
  try {
    const user = await getUserForVerification(req.username);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    res.json({
      username: user.username,
      email: user.email || null,
      email_verified: user.email_verified === 1
    });
  } catch (err) {
    console.error('Me error:', err.message);
    res.status(500).json({ error: '服务器错误' });
  }
});

// 发送验证码到当前绑定邮箱（用于改密/换绑等敏感操作验证）
app.post('/api/auth/send-code', checkAdmin, async (req, res) => {
  try {
    const user = await getUserForVerification(req.username);
    if (!user || !user.email) {
      return res.status(400).json({ error: '请先绑定邮箱' });
    }

    // Rate limit
    const existing = codeStore.get(req.username);
    if (existing && existing.lastSent && (Date.now() - existing.lastSent) < CODE_COOLDOWN) {
      const remain = Math.ceil((CODE_COOLDOWN - (Date.now() - existing.lastSent)) / 1000);
      return res.status(429).json({ error: `请 ${remain} 秒后再发送` });
    }

    const code = String(crypto.randomInt(100000, 999999));
    const expires = Date.now() + CODE_TTL;
    codeStore.set(req.username, { code, expires, lastSent: Date.now() });

    const transporter = getMailer();
    if (!transporter) {
      codeStore.delete(req.username);
      return res.status(500).json({ error: '邮件服务未配置，请联系管理员' });
    }
    try {
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: user.email,
        subject: '博客管理 - 安全验证码',
        html: `<p>您正在进行敏感操作验证。验证码是：<strong style="font-size:24px;letter-spacing:4px">${code}</strong></p><p>验证码 5 分钟内有效，请勿泄露。</p>`
      });
      res.json({ ok: true, message: '验证码已发送', maskedEmail: user.email.replace(/(.{3}).*(@.*)/, '$1***$2') });
    } catch (mailErr) {
      codeStore.delete(req.username);
      console.error('Send-code mail error:', mailErr.message);
      return res.status(500).json({ error: '邮件发送失败' });
    }
  } catch (err) {
    console.error('Send-code error:', err.message);
    res.status(500).json({ error: '发送失败' });
  }
});

app.post('/api/auth/bind-email', checkAdmin, async (req, res) => {
  const { email, code } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: '请输入有效的邮箱地址' });
  }

  try {
    const user = await getUserForVerification(req.username);
    if (!user) return res.status(404).json({ error: '用户不存在' });

    // If already verified, must verify current email first
    if (user.email_verified === 1) {
      if (!code || code.length !== 6) {
        return res.status(400).json({ error: '请先通过当前邮箱验证' });
      }
      const stored = codeStore.get(req.username);
      if (!stored || Date.now() > stored.expires || String(stored.code) !== String(code)) {
        codeStore.delete(req.username);
        return res.status(400).json({ error: '验证码错误或已过期' });
      }
    }

    // Rate limit for sending new code
    const existing = codeStore.get(req.username);
    if (existing && existing.lastSent && (Date.now() - existing.lastSent) < CODE_COOLDOWN) {
      const remain = Math.ceil((CODE_COOLDOWN - (Date.now() - existing.lastSent)) / 1000);
      return res.status(429).json({ error: `请 ${remain} 秒后再发送` });
    }

    const newCode = String(crypto.randomInt(100000, 999999));
    const expires = Date.now() + CODE_TTL;

    // Update email in MySQL (mark as unverified on rebind)
    await updateUserEmail(req.username, email);

    // Store new code
    codeStore.set(req.username, { code: newCode, expires, lastSent: Date.now() });

    // Send new code to new email
    const transporter = getMailer();
    if (!transporter) {
      codeStore.delete(req.username);
      return res.status(500).json({ error: '邮件服务未配置，请联系管理员' });
    }
    try {
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject: '博客管理 - 邮箱验证码',
        html: `<p>您的邮箱验证码是：<strong style="font-size:24px;letter-spacing:4px">${newCode}</strong></p><p>验证码 5 分钟内有效，请勿泄露。</p>`
      });
      res.json({ ok: true, message: '验证码已发送' });
    } catch (mailErr) {
      codeStore.delete(req.username);
      console.error('Bind-email mail error:', mailErr.message);
      return res.status(500).json({ error: '邮件发送失败' });
    }
  } catch (err) {
    console.error('Bind-email error:', err.message);
    codeStore.delete(req.username);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: '该邮箱已被其他账户绑定' });
    }
    res.status(500).json({ error: '发送失败，请稍后重试' });
  }
});

app.post('/api/auth/verify-email', checkAdmin, codeVerifyLimiter, (req, res) => {
  const { code } = req.body;
  if (!code || code.length !== 6) {
    return res.status(400).json({ error: '请输入6位验证码' });
  }

  const stored = codeStore.get(req.username);
  if (!stored) {
    return res.status(400).json({ error: '验证码错误或已过期' });
  }
  if (Date.now() > stored.expires) {
    codeStore.delete(req.username);
    return res.status(400).json({ error: '验证码已过期，请重新发送' });
  }
  if (String(stored.code) !== String(code)) {
    return res.status(400).json({ error: '验证码错误或已过期' });
  }

  verifyUserEmail(req.username)
    .then(() => {
      codeStore.delete(req.username);
      res.json({ ok: true, message: '邮箱验证成功' });
    })
    .catch(err => {
      console.error('Verify-email error:', err.message);
      res.status(500).json({ error: '服务器错误' });
    });
});

app.post('/api/auth/unbind-email', checkAdmin, codeVerifyLimiter, async (req, res) => {
  const { code } = req.body;
  if (!code || code.length !== 6) {
    return res.status(400).json({ error: '请输入验证码' });
  }

  try {
    const user = await getUserForVerification(req.username);
    if (!user || !user.email) {
      return res.status(400).json({ error: '未绑定邮箱' });
    }

    const stored = codeStore.get(req.username);
    if (!stored || Date.now() > stored.expires || String(stored.code) !== String(code)) {
      codeStore.delete(req.username);
      return res.status(400).json({ error: '验证码错误或已过期' });
    }

    codeStore.delete(req.username);
    await unbindUserEmail(req.username);
    res.json({ ok: true, message: '邮箱已解绑' });
  } catch (err) {
    console.error('Unbind-email error:', err.message);
    res.status(500).json({ error: '服务器错误' });
  }
});

app.post('/api/auth/change-username', checkAdmin, async (req, res) => {
  const { newUsername } = req.body;
  if (!newUsername || !newUsername.trim()) {
    return res.status(400).json({ error: '请输入新用户名' });
  }
  if (newUsername === req.username) {
    return res.status(400).json({ error: '新用户名与当前一致' });
  }
  try {
    const existing = await findUserByUsername(newUsername);
    if (existing) {
      return res.status(400).json({ error: '该用户名已被使用' });
    }
    await updateUserUsername(req.username, newUsername);
    if (req.tokenJti) tokenBlacklist.set(req.tokenJti, req.tokenExp * 1000);
    res.json({ ok: true, newUsername });
  } catch (err) {
    console.error('Change-username error:', err.message);
    res.status(500).json({ error: '服务器错误' });
  }
});

app.post('/api/auth/send-reset-code', resetLimiter, async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: '请输入账户名' });
  }
  try {
    const user = await getUserForVerification(username);
    if (!user) return res.status(400).json({ error: '账户不存在' });
    if (!user.email) return res.status(400).json({ error: '该账户未绑定邮箱，无法重置密码' });

    const existing = codeStore.get(username);
    if (existing && existing.lastSent && (Date.now() - existing.lastSent) < CODE_COOLDOWN) {
      const remain = Math.ceil((CODE_COOLDOWN - (Date.now() - existing.lastSent)) / 1000);
      return res.status(429).json({ error: `请 ${remain} 秒后再发送` });
    }

    const code = String(crypto.randomInt(100000, 999999));
    const expires = Date.now() + CODE_TTL;
    codeStore.set(username, { code, expires, lastSent: Date.now() });

    const transporter = getMailer();
    if (!transporter) {
      codeStore.delete(req.username);
      return res.status(500).json({ error: '邮件服务未配置，请联系管理员' });
    }
    try {
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: user.email,
        subject: '博客管理 - 密码重置验证码',
        html: `<p>您正在重置密码。验证码是：<strong style="font-size:24px;letter-spacing:4px">${code}</strong></p><p>验证码 5 分钟内有效，请勿泄露。</p>`
      });
      res.json({ ok: true, message: '验证码已发送', maskedEmail: user.email.replace(/(.{3}).*(@.*)/, '$1***$2') });
    } catch (mailErr) {
      codeStore.delete(username);
      console.error('Send-reset-code mail error:', mailErr.message);
      return res.status(500).json({ error: '邮件发送失败' });
    }
  } catch (err) {
    console.error('Send-reset-code error:', err.message);
    res.status(500).json({ error: '发送失败' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { username, newPassword, code } = req.body;
  if (!username || !newPassword) {
    return res.status(400).json({ error: '请输入账户和新密码' });
  }
  if (newPassword.length < 8 || newPassword.length > 32 ||
      !/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) ||
      !/[0-9]/.test(newPassword)) {
    return res.status(400).json({ error: '密码需8-32位，包含大小写字母和数字' });
  }
  try {
    const user = await findUserByUsername(username);
    if (!user) return res.status(400).json({ error: '账户不存在' });
    if (!user.email) return res.status(400).json({ error: '该账户未绑定邮箱，无法重置密码' });

    if (!code || code.length !== 6) {
      return res.status(400).json({ error: '请先发送并输入邮箱验证码' });
    }
    const stored = codeStore.get(username);
    if (!stored || Date.now() > stored.expires || String(stored.code) !== String(code)) {
      codeStore.delete(username);
      return res.status(400).json({ error: '验证码错误或已过期' });
    }
    codeStore.delete(username);

    const newHash = await bcrypt.hash(newPassword, 10);
    await updatePasswordHash(username, newHash);
    res.json({ ok: true });
  } catch (err) {
    console.error('Reset-password error:', err.message);
    res.status(500).json({ error: '服务器错误' });
  }
});

// ── Post helpers ──

function readPosts() {
  if (!fs.existsSync(POSTS_DIR)) fs.mkdirSync(POSTS_DIR, { recursive: true });
  const files = fs.readdirSync(POSTS_DIR).filter(f => f.endsWith('.json'));
  return files
    .map(f => {
      try { return JSON.parse(fs.readFileSync(path.join(POSTS_DIR, f), 'utf8')); }
      catch { return null; }
    })
    .filter(Boolean)
    .sort((a, b) => b.id - a.id);
}

function writePost(post) {
  fs.writeFileSync(
    path.join(POSTS_DIR, `${post.id}.json`),
    JSON.stringify(post, null, 2),
    'utf8'
  );
}

function deletePostFile(id) {
  const filePath = path.join(POSTS_DIR, `${id}.json`);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
}

// ── Post APIs ──

// Post ID validation: only numeric, prevents path traversal
function validatePostId(id) {
  return /^\d+$/.test(id);
}

app.get('/api/posts', (_req, res) => res.json(readPosts()));

app.get('/api/posts/:id', (req, res) => {
  if (!validatePostId(req.params.id)) return res.status(400).json({ error: '无效的文章ID' });
  const filePath = path.join(POSTS_DIR, `${req.params.id}.json`);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: '文章不存在' });
  res.json(JSON.parse(fs.readFileSync(filePath, 'utf8')));
});

app.post('/api/posts', checkAdmin, (req, res) => {
  const { title, date, excerpt, content, images, tags } = req.body;
  if (!title || !date || !content) {
    return res.status(400).json({ error: '标题、日期和内容为必填项' });
  }
  const posts = readPosts();
  const id = posts.length > 0 ? Math.max(...posts.map(p => p.id)) + 1 : 1;
  const cleanTags = (tags || []).filter(t => t && t.trim()).slice(0, 4).map(t => t.trim());
  const post = { id, title, date, excerpt: excerpt || '', content: sanitizeHtml(content, POST_SANITIZE), images: images || [], tags: cleanTags };
  writePost(post);
  res.status(201).json(post);
});

app.put('/api/posts/:id', checkAdmin, (req, res) => {
  if (!validatePostId(req.params.id)) return res.status(400).json({ error: '无效的文章ID' });
  const filePath = path.join(POSTS_DIR, `${req.params.id}.json`);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: '文章不存在' });
  const existing = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const { title, date, excerpt, content, images, tags } = req.body;
  const cleanTags = tags !== undefined
    ? (tags || []).filter(t => t && t.trim()).slice(0, 4).map(t => t.trim())
    : (existing.tags || []);
  const updated = {
    id: existing.id,
    title: title || existing.title,
    date: date || existing.date,
    excerpt: excerpt !== undefined ? excerpt : existing.excerpt,
    content: content ? sanitizeHtml(content, POST_SANITIZE) : existing.content,
    images: images !== undefined ? images : (existing.images || []),
    tags: cleanTags
  };
  writePost(updated);
  res.json(updated);
});

app.delete('/api/posts/:id', checkAdmin, (req, res) => {
  if (!validatePostId(req.params.id)) return res.status(400).json({ error: '无效的文章ID' });
  const filePath = path.join(POSTS_DIR, `${req.params.id}.json`);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: '文章不存在' });
  deletePostFile(req.params.id);
  res.json({ ok: true });
});

// ── Config APIs ──

app.get('/api/config', (_req, res) => {
  const defaults = { title: '我的博客', subtitle: '写点想写的东西。', footer: '© 2026 我的博客', links: [] };
  if (!fs.existsSync(CONFIG_PATH)) {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(defaults, null, 2), 'utf8');
  }
  res.json(JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')));
});

app.put('/api/config', checkAdmin, (req, res) => {
  const current = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  const ALLOWED = ['title', 'subtitle', 'footer', 'links', 'background', 'profile'];
  const updated = { ...current };
  for (const key of ALLOWED) {
    if (req.body[key] !== undefined) {
      if (key === 'subtitle' && typeof req.body[key] === 'string') {
        updated[key] = sanitizeHtml(req.body[key], SUBTITLE_SANITIZE);
      } else {
        updated[key] = req.body[key];
      }
    }
  }
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(updated, null, 2), 'utf8');
  res.json(updated);
});

// ── Timeline helpers ──

const TIMELINE_DEFAULTS = { events: [] };

function readTimeline() {
  if (!fs.existsSync(TIMELINE_PATH)) {
    fs.writeFileSync(TIMELINE_PATH, JSON.stringify(TIMELINE_DEFAULTS, null, 2), 'utf8');
    return JSON.parse(JSON.stringify(TIMELINE_DEFAULTS));
  }
  return JSON.parse(fs.readFileSync(TIMELINE_PATH, 'utf8'));
}

function writeTimeline(data) {
  fs.writeFileSync(TIMELINE_PATH, JSON.stringify(data, null, 2), 'utf8');
}

// ── Timeline APIs ──

app.get('/api/timeline', (_req, res) => {
  const data = readTimeline();
  data.events.sort((a, b) => new Date(a.date) - new Date(b.date));
  res.json(data.events);
});

app.post('/api/timeline', checkAdmin, (req, res) => {
  const { date, title, description, icon } = req.body;
  if (!date || !title) {
    return res.status(400).json({ error: '日期和标题为必填项' });
  }
  const data = readTimeline();
  const id = data.events.length > 0 ? Math.max(...data.events.map(e => e.id)) + 1 : 1;
  const event = { id, date, title, description: description || '', icon: icon || '' };
  data.events.push(event);
  writeTimeline(data);
  res.status(201).json(event);
});

app.put('/api/timeline/:id', checkAdmin, (req, res) => {
  const data = readTimeline();
  const idx = data.events.findIndex(e => e.id === +req.params.id);
  if (idx === -1) return res.status(404).json({ error: '事件不存在' });
  const { date, title, description, icon } = req.body;
  data.events[idx] = {
    id: data.events[idx].id,
    date: date || data.events[idx].date,
    title: title || data.events[idx].title,
    description: description !== undefined ? description : data.events[idx].description,
    icon: icon !== undefined ? icon : data.events[idx].icon,
  };
  writeTimeline(data);
  res.json(data.events[idx]);
});

app.delete('/api/timeline/:id', checkAdmin, (req, res) => {
  const data = readTimeline();
  const idx = data.events.findIndex(e => e.id === +req.params.id);
  if (idx === -1) return res.status(404).json({ error: '事件不存在' });
  data.events.splice(idx, 1);
  writeTimeline(data);
  res.json({ ok: true });
});

// ── Messages helpers ──

function readMessages() {
  if (!fs.existsSync(MESSAGES_FILE)) {
    fs.writeFileSync(MESSAGES_FILE, '[]', 'utf8');
    return [];
  }
  return JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8'));
}

function writeMessages(msgs) {
  fs.writeFileSync(MESSAGES_FILE, JSON.stringify(msgs, null, 2), 'utf8');
}

// ── Messages APIs ──

// Public: submit a message
app.post('/api/messages', messageLimiter, (req, res) => {
  const { nickname, content, context, postId } = req.body;
  if (!nickname || !nickname.trim() || nickname.length > 20) {
    return res.status(400).json({ error: '昵称需1-20个字符' });
  }
  if (!content || !content.trim()) {
    return res.status(400).json({ error: '留言内容不能为空' });
  }
  const trimmed = content.trim().slice(0, 50);
  const msg = {
    id: Date.now(),
    nickname: nickname.trim().slice(0, 20),
    content: trimmed,
    time: new Date().toISOString(),
    approved: false,
    context: context === 'article' ? 'article' : 'profile',
    postId: context === 'article' && Number.isInteger(postId) ? postId : null
  };
  const msgs = readMessages();
  msgs.push(msg);
  writeMessages(msgs);
  res.status(201).json({ message: '留言已提交，待审核后显示' });
});

// Public: get approved messages
app.get('/api/messages', (req, res) => {
  const msgs = readMessages();
  let approved = msgs.filter(m => m.approved);
  if (req.query.postId) {
    const pid = parseInt(req.query.postId);
    if (!isNaN(pid)) approved = approved.filter(m => m.context === 'article' && m.postId === pid);
  } else {
    approved = approved.filter(m => m.context !== 'article');
  }
  approved.sort((a, b) => b.id - a.id);
  res.json(approved.slice(0, 50));
});

// Admin: get all messages
app.get('/api/admin/messages', checkAdmin, (_req, res) => {
  const msgs = readMessages();
  msgs.sort((a, b) => b.id - a.id);
  res.json(msgs);
});

// Admin: update message (approve/reject)
app.put('/api/admin/messages/:id', checkAdmin, (req, res) => {
  const msgs = readMessages();
  const idx = msgs.findIndex(m => m.id === +req.params.id);
  if (idx === -1) return res.status(404).json({ error: '留言不存在' });
  if (req.body.approved !== undefined) {
    msgs[idx].approved = !!req.body.approved;
  }
  writeMessages(msgs);
  res.json(msgs[idx]);
});

// Admin: delete message
app.delete('/api/admin/messages/:id', checkAdmin, (req, res) => {
  const msgs = readMessages();
  const idx = msgs.findIndex(m => m.id === +req.params.id);
  if (idx === -1) return res.status(404).json({ error: '留言不存在' });
  msgs.splice(idx, 1);
  writeMessages(msgs);
  res.json({ ok: true });
});

// Magic bytes validation for uploaded files
function checkMagic(buf, ext) {
  const magicMap = {
    '.jpg': [0xFF, 0xD8, 0xFF],
    '.jpeg': [0xFF, 0xD8, 0xFF],
    '.png': [0x89, 0x50, 0x4E, 0x47],
    '.gif': [0x47, 0x49, 0x46],
    '.webp': [0x52, 0x49, 0x46, 0x46],
    '.mp4': null,
    '.webm': [0x1A, 0x45, 0xDF, 0xA3],
    '.mov': null
  };
  if (ext === '.mp4' || ext === '.mov') {
    if (buf.length < 12) return false;
    return buf[4] === 0x66 && buf[5] === 0x74 && buf[6] === 0x79 && buf[7] === 0x70;
  }
  const expected = magicMap[ext];
  if (!expected) return false;
  for (let i = 0; i < expected.length; i++) {
    if (buf[i] !== expected[i]) return false;
  }
  return true;
}

// ── 图片上传 ──
const uploadDir = path.join(__dirname, 'images', 'posts');
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + '_' + Math.random().toString(36).slice(2, 8) + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  }
});

// 背景上传
const bgStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, path.join(__dirname, 'images', 'bg')),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, 'bg_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8) + ext);
  }
});
const uploadBg = multer({
  storage: bgStorage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp', '.gif', '.mp4', '.webm', '.mov'];
    cb(null, allowed.includes(path.extname(file.originalname).toLowerCase()));
  }
});

// 头像上传
const avatarStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, path.join(__dirname, 'images', 'avatars')),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, 'avatar_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8) + ext);
  }
});
const uploadAvatar = multer({
  storage: avatarStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
    cb(null, allowed.includes(path.extname(file.originalname).toLowerCase()));
  }
});

// GET /api/visits?days=30
app.get('/api/visits', checkAdmin, (req, res) => {
  const days = parseInt(req.query.days) || 30;
  const result = [];
  const today = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    result.push({ date: key, count: visits[key] || 0 });
  }
  res.json(result);
});

app.post('/api/upload', checkAdmin, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: '请选择图片文件' });
  const filePath = path.join(uploadDir, req.file.filename);
  const ext = path.extname(req.file.originalname).toLowerCase();
  const buf = fs.readFileSync(filePath).slice(0, 12);
  if (!checkMagic(buf, ext)) { fs.unlinkSync(filePath); return res.status(400).json({ error: '文件内容与扩展名不符' }); }
  const url = '/images/posts/' + req.file.filename;
  res.json({ url });
});

app.post('/api/upload-avatar', checkAdmin, uploadAvatar.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: '请选择头像文件' });
  const filePath = path.join(__dirname, 'images', 'avatars', req.file.filename);
  const ext = path.extname(req.file.originalname).toLowerCase();
  const buf = fs.readFileSync(filePath).slice(0, 12);
  if (!checkMagic(buf, ext)) { fs.unlinkSync(filePath); return res.status(400).json({ error: '文件内容与扩展名不符' }); }
  const url = '/images/avatars/' + req.file.filename;
  res.json({ url });
});

app.post('/api/upload-bg', checkAdmin, uploadBg.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: '请选择文件' });
  const filePath = path.join(__dirname, 'images', 'bg', req.file.filename);
  const ext = path.extname(req.file.originalname).toLowerCase();
  const buf = fs.readFileSync(filePath).slice(0, 12);
  if (!checkMagic(buf, ext)) { fs.unlinkSync(filePath); return res.status(400).json({ error: '文件内容与扩展名不符' }); }
  const url = '/images/bg/' + req.file.filename;
  res.json({ url });
});

// ── Start ──

// Persist visits on exit
process.on('SIGINT', () => { saveVisits(); process.exit(); });
process.on('SIGTERM', () => { saveVisits(); process.exit(); });
process.on('exit', () => saveVisits());

initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`博客服务已启动: http://localhost:${PORT}`);
      console.log(`管理后台: http://localhost:${PORT}/admin.html`);
    });
  })
  .catch(err => {
    console.error('DB init failed:', err.message);
    process.exit(1);
  });
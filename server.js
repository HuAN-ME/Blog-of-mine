require('dotenv').config();

const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const POSTS_DIR = path.join(__dirname, 'posts');
const CONFIG_PATH = path.join(__dirname, 'config.json');
const TIMELINE_PATH = path.join(__dirname, 'timeline.json');
const VISITS_FILE = path.join(__dirname, 'visits.json');

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

// Token store: { token -> { username, expiresAt } }
const tokens = new Map();
const TOKEN_TTL = 24 * 60 * 60 * 1000; // 24 hours

// Verification code store (in-memory): { username -> { code, expires, lastSent } }
const codeStore = new Map();
const CODE_TTL = 5 * 60 * 1000; // 5 minutes
const CODE_COOLDOWN = 60 * 1000; // 1 minute between resends

app.use(express.json());

// Visit tracking middleware
app.use((req, res, next) => {
  if (req.method === 'GET' && (req.path === '/' || req.path === '/index.html')) {
    const today = new Date().toISOString().slice(0, 10);
    visits[today] = (visits[today] || 0) + 1;
    if (visits[today] % 10 === 0) saveVisits();
  }
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
      // If no users.json and no admin, create default admin
      if (!fs.existsSync(usersPath)) {
        const hash = await bcrypt.hash('Admin123!', 10);
        await conn.execute(
          'INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)',
          [uuidv4(), 'admin', hash]
        );
        console.log('[DB] default admin account created (admin / Admin123!)');
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
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未登录' });
  }
  const token = auth.slice(7);
  const session = tokens.get(token);
  if (!session || session.expiresAt < Date.now()) {
    tokens.delete(token);
    return res.status(401).json({ error: '登录已过期' });
  }
  req.username = session.username;
  next();
}

// ── Auth APIs ──

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '请输入账户和密码' });
  }
  try {
    const user = await findUserByUsername(username);
    if (!user) return res.status(401).json({ error: '账户或密码错误' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: '账户或密码错误' });
    const token = uuidv4();
    tokens.set(token, { username, expiresAt: Date.now() + TOKEN_TTL });
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
  const auth = req.headers['authorization'];
  tokens.delete(auth.slice(7));
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

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expires = Date.now() + CODE_TTL;
    codeStore.set(req.username, { code, expires, lastSent: Date.now() });

    const transporter = getMailer();
    if (transporter) {
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: user.email,
        subject: '博客管理 - 安全验证码',
        html: `<p>您正在进行敏感操作验证。验证码是：<strong style="font-size:24px;letter-spacing:4px">${code}</strong></p><p>验证码 5 分钟内有效，请勿泄露。</p>`
      });
    }
    res.json({ ok: true, message: '验证码已发送', maskedEmail: user.email.replace(/(.{3}).*(@.*)/, '$1***$2') });
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

    const newCode = String(Math.floor(100000 + Math.random() * 900000));
    const expires = Date.now() + CODE_TTL;

    // Update email in MySQL (mark as unverified on rebind)
    await updateUserEmail(req.username, email);

    // Store new code
    codeStore.set(req.username, { code: newCode, expires, lastSent: Date.now() });

    // Send new code to new email
    const transporter = getMailer();
    if (transporter) {
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject: '博客管理 - 邮箱验证码',
        html: `<p>您的邮箱验证码是：<strong style="font-size:24px;letter-spacing:4px">${newCode}</strong></p><p>验证码 5 分钟内有效，请勿泄露。</p>`
      });
    }
    res.json({ ok: true, message: '验证码已发送' });
  } catch (err) {
    console.error('Bind-email error:', err.message);
    codeStore.delete(req.username);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: '该邮箱已被其他账户绑定' });
    }
    res.status(500).json({ error: '发送失败，请稍后重试' });
  }
});

app.post('/api/auth/verify-email', checkAdmin, (req, res) => {
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

app.post('/api/auth/unbind-email', checkAdmin, async (req, res) => {
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
    // Invalidate all tokens for old username
    for (const [tok, sess] of tokens) {
      if (sess.username === req.username) tokens.delete(tok);
    }
    res.json({ ok: true, newUsername });
  } catch (err) {
    console.error('Change-username error:', err.message);
    res.status(500).json({ error: '服务器错误' });
  }
});

app.post('/api/auth/send-reset-code', async (req, res) => {
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

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expires = Date.now() + CODE_TTL;
    codeStore.set(username, { code, expires, lastSent: Date.now() });

    const transporter = getMailer();
    if (transporter) {
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: user.email,
        subject: '博客管理 - 密码重置验证码',
        html: `<p>您正在重置密码。验证码是：<strong style="font-size:24px;letter-spacing:4px">${code}</strong></p><p>验证码 5 分钟内有效，请勿泄露。</p>`
      });
    }
    res.json({ ok: true, message: '验证码已发送', maskedEmail: user.email.replace(/(.{3}).*(@.*)/, '$1***$2') });
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

app.get('/api/posts', (_req, res) => res.json(readPosts()));

app.get('/api/posts/:id', (req, res) => {
  const filePath = path.join(POSTS_DIR, `${req.params.id}.json`);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: '文章不存在' });
  res.json(JSON.parse(fs.readFileSync(filePath, 'utf8')));
});

app.post('/api/posts', checkAdmin, (req, res) => {
  const { title, date, excerpt, content, images } = req.body;
  if (!title || !date || !content) {
    return res.status(400).json({ error: '标题、日期和内容为必填项' });
  }
  const posts = readPosts();
  const id = posts.length > 0 ? Math.max(...posts.map(p => p.id)) + 1 : 1;
  const post = { id, title, date, excerpt: excerpt || '', content, images: images || [] };
  writePost(post);
  res.status(201).json(post);
});

app.put('/api/posts/:id', checkAdmin, (req, res) => {
  const filePath = path.join(POSTS_DIR, `${req.params.id}.json`);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: '文章不存在' });
  const existing = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const { title, date, excerpt, content, images } = req.body;
  const updated = {
    id: existing.id,
    title: title || existing.title,
    date: date || existing.date,
    excerpt: excerpt !== undefined ? excerpt : existing.excerpt,
    content: content || existing.content,
    images: images !== undefined ? images : (existing.images || [])
  };
  writePost(updated);
  res.json(updated);
});

app.delete('/api/posts/:id', checkAdmin, (req, res) => {
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
  const updated = { ...current, ...req.body };
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
  const url = '/images/posts/' + req.file.filename;
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
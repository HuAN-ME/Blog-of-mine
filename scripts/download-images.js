const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

const BASE = path.join(__dirname, '..', 'images');

const tasks = [
  { url: 'https://public.ysjf.com/mediastorm/material/material/%E8%B4%B9%E5%B0%94%E7%8F%AD%E5%85%8B%E6%96%AF-20-%E8%BF%9C%E6%99%AF-20250107.JPG', dest: 'bg/background.webp' },
  { url: 'https://www.toopic.cn/public/uploads/small/1715140733917171514073321.jpg', dest: 'avatars/avatar.webp' },
  { url: 'https://fastcdn.mihoyo.com/content-v2/nap/102198/5b9694391a83cba8a7bcbb8632c80dda_3178615340270331633.png', dest: 'posts/3/mihoyo.webp' },
  { url: 'https://picsum.photos/800/450', dest: 'posts/5/carousel-1.webp' },
  { url: 'https://picsum.photos/800/451', dest: 'posts/5/carousel-2.webp' },
];

function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const fullPath = path.join(BASE, destPath);
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    const proto = url.startsWith('https') ? https : http;
    const req = proto.get(url, (res) => {
      // Follow redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        console.log(`  [redirect] ${url} → ${res.headers.location}`);
        return downloadFile(res.headers.location, destPath).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`HTTP ${res.statusCode}: ${url}`));
      }
      const file = fs.createWriteStream(fullPath);
      res.pipe(file);
      file.on('finish', () => { file.close(); resolve(); });
      file.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('timeout')); });
  });
}

(async () => {
  let ok = 0, fail = 0;
  for (const t of tasks) {
    process.stdout.write(`[${t.dest}] ${t.url} ... `);
    try {
      await downloadFile(t.url, t.dest);
      console.log('OK');
      ok++;
    } catch (e) {
      console.log(`FAIL: ${e.message}`);
      fail++;
    }
  }
  console.log(`\nDone: ${ok} ok, ${fail} failed`);
})();
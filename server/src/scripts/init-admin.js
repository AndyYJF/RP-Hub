import bcrypt from 'bcryptjs';
import { db, now } from '../db.js';
import { config } from '../config.js';

const username = config.adminUsername;
const password = config.adminPassword;

const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
if (existing) {
  console.log(`管理员账号 "${username}" 已存在，跳过创建。如需重置密码请使用：`);
  console.log(`  node -e "import('./src/db.js').then(async m=>{const b=await import('bcryptjs');m.db.prepare('UPDATE users SET password_hash=? WHERE username=?').run(b.default.hashSync(process.argv[1],10),process.argv[2]);console.log('done');})" "${password}" "${username}"`);
  process.exit(0);
}

const hash = bcrypt.hashSync(password, 10);
db.prepare(
  `INSERT INTO users (username, password_hash, role, status, created_at) VALUES (?, ?, 'admin', 'active', ?)`
).run(username, hash, now());
console.log(`✅ 管理员账号已创建：${username}`);
console.log(`   请立即登录并修改密码！`);
process.exit(0);

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import path from 'path';
import fs from 'fs';
import { config } from './config.js';
import { errorHandler, notFound } from './middleware/error.js';
import authRoutes from './routes/auth.js';
import syncRoutes from './routes/sync.js';
import libraryRoutes from './routes/library.js';
import adminRoutes from './routes/admin.js';
import announcementsRoutes from './routes/announcements.js';
import proxyRoutes from './routes/proxy.js';

const app = express();

// ---------- Security & parsing ----------
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '12mb' }));
app.use(express.urlencoded({ extended: true, limit: '12mb' }));

const origins = config.corsOrigin === '*'
  ? '*'
  : config.corsOrigin.split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: origins === '*' ? true : origins,
  credentials: true,
}));
app.use(morgan('tiny'));

// ---------- Health ----------
app.get('/api/health', (_req, res) => res.json({ ok: true, ts: Date.now() }));
app.get('/api/config', (_req, res) => res.json({
  allowRegister: config.allowRegister,
  jwtExpiresIn: config.jwtExpiresIn,
}));

// ---------- API routes ----------
app.use('/api/auth', authRoutes);
app.use('/api/sync', syncRoutes);
app.use('/api/library', libraryRoutes);
app.use('/api/announcements', announcementsRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/proxy', proxyRoutes);

// ---------- Static frontend hosting (optional) ----------
if (config.staticDir && fs.existsSync(config.staticDir)) {
  app.use(express.static(config.staticDir));
  // SPA fallback (avoid catching /api/*)
  app.get(/^\/(?!api).*/, (req, res, next) => {
    const indexPath = path.join(config.staticDir, 'index.html');
    if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
    next();
  });
}

// ---------- 404 & errors ----------
app.use(notFound);
app.use(errorHandler);

app.listen(config.port, () => {
  console.log(`RP-Hub server listening on http://0.0.0.0:${config.port}`);
  console.log(`DB at: ${config.dbPath}`);
  console.log(`Allow register: ${config.allowRegister}`);
});

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import path from 'path';
import fs from 'fs';
import { config } from './config.js';
import { validateProductionConfig } from './utils/validateConfig.js';
import { errorHandler, notFound } from './middleware/error.js';
import authRoutes from './routes/auth.js';
import syncRoutes from './routes/sync.js';
import libraryRoutes from './routes/library.js';
import adminRoutes from './routes/admin.js';
import announcementsRoutes from './routes/announcements.js';
import proxyRoutes from './routes/proxy.js';
import chatProxyRoutes from './routes/chatProxy.js';
import imageCacheRoutes from './routes/imageCache.js';

validateProductionConfig();

const app = express();

// ---------- Security & parsing ----------
const cspDirectives = {
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'https://cdn.tailwindcss.com', 'https://unpkg.com', 'https://cdn.jsdelivr.net'],
  styleSrc: ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com', 'https://fonts.googleapis.com'],
  fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
  imgSrc: ["'self'", 'data:', 'blob:', 'https:', 'http:'],
  connectSrc: ["'self'", 'https:', 'http:', 'ws:', 'wss:'],
  frameSrc: ["'self'", 'blob:'],
  objectSrc: ["'none'"],
  baseUri: ["'self'"],
  formAction: ["'self'"],
};

app.use(helmet({
  contentSecurityPolicy: process.env.CONTENT_SECURITY_POLICY === 'false'
    ? false
    : { directives: cspDirectives },
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));
app.use(express.json({ limit: '64mb' }));
app.use(express.urlencoded({ extended: true, limit: '64mb' }));

const origins = config.corsOrigin === '*'
  ? '*'
  : config.corsOrigin.split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: origins === '*' ? true : origins,
  credentials: true,
}));
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('tiny'));
}

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
app.use('/api/proxy', chatProxyRoutes);
app.use('/api/image-cache', imageCacheRoutes);

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

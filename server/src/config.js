import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const resolveBool = (v, fallback) => {
  if (v === undefined || v === null || v === '') return fallback;
  return String(v).toLowerCase() === 'true' || v === '1';
};

export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  jwtSecret: process.env.JWT_SECRET || 'dev-secret-please-change',
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret-please-change',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '15m',
  jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d',
  adminUsername: process.env.ADMIN_USERNAME || 'admin',
  adminPassword: process.env.ADMIN_PASSWORD || 'please-change-immediately',
  allowRegister: resolveBool(process.env.ALLOW_REGISTER, true),
  dbPath: process.env.DB_PATH
    ? path.resolve(__dirname, '..', process.env.DB_PATH)
    : path.resolve(__dirname, '../data/rphub.db'),
  staticDir: process.env.STATIC_DIR
    ? path.resolve(__dirname, '..', process.env.STATIC_DIR)
    : '',
  corsOrigin: process.env.CORS_ORIGIN || '*',
};

export const __dirname_export = __dirname;

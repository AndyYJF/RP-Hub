import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { config } from '../config.js';

export function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );
}

export function signRefreshToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, type: 'refresh' },
    config.jwtRefreshSecret,
    { expiresIn: config.jwtRefreshExpiresIn }
  );
}

export function hashRefreshToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function verifyAccessToken(token) {
  try {
    return jwt.verify(token, config.jwtSecret);
  } catch (e) {
    return null;
  }
}

export function verifyRefreshToken(token) {
  try {
    return jwt.verify(token, config.jwtRefreshSecret);
  } catch (e) {
    return null;
  }
}

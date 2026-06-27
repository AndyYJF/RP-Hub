import { db } from '../db.js';

/**
 * api_quota <= 0 means unlimited.
 * Otherwise total_tokens in api_usage must stay below the cap.
 */
export function assertApiQuota(userId) {
  const user = db.prepare('SELECT api_quota FROM users WHERE id = ?').get(userId);
  if (!user || user.api_quota <= 0) return;

  const used = db.prepare(
    'SELECT COALESCE(SUM(total_tokens), 0) AS total FROM api_usage WHERE user_id = ?'
  ).get(userId).total;

  if (used >= user.api_quota) {
    const err = new Error('API 配额已用尽，请联系管理员');
    err.status = 429;
    throw err;
  }
}

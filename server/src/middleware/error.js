export function errorHandler(err, req, res, _next) {
  console.error('[ERROR]', err);
  if (res.headersSent) return;
  const status = err.status || 500;
  res.status(status).json({
    error: err.message || '服务器内部错误',
    code: err.code || 'INTERNAL_ERROR',
  });
}

export function notFound(req, res) {
  res.status(404).json({ error: '接口不存在' });
}

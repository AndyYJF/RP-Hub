# Dockerfile for RP-Hub backend
# Uses Node 24+ for built-in node:sqlite (no native compilation needed)
FROM node:24-alpine

WORKDIR /app

# Copy package files and install deps
COPY server/package*.json ./
RUN npm install --omit=dev --no-audit --no-fund

# Copy server source
COPY server/src ./src

# Copy frontend static files (served by backend when STATIC_DIR=/public)
COPY index.html account.html admin.html ./public/
COPY assets ./public/assets
COPY character ./public/character

ENV STATIC_DIR=/public
ENV DB_PATH=/data/rphub.db
ENV NODE_ENV=production

# Expose port
EXPOSE 3000

# Persistent data volume
VOLUME ["/data"]

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1

# Initialize admin on first run, then start server
CMD ["sh", "-c", "node src/scripts/init-admin.js && node src/index.js"]

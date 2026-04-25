# ── Stage 1: Build ────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app
RUN apk add --no-cache python3 make g++
COPY package*.json ./
RUN npm ci --only=production --ignore-scripts
COPY . .
RUN npm run build 2>/dev/null || true

# ── Stage 2: Production (minimal attack surface) ──────────────
FROM node:20-alpine AS production

# Security: create non-root user
RUN addgroup -g 1001 -S appgroup \
 && adduser  -u 1001 -S appuser -G appgroup \
 && apk add --no-cache dumb-init

WORKDIR /app

# Copy only what's needed
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
COPY --from=builder --chown=appuser:appgroup /app/package.json ./

# Security hardening
RUN chmod -R 550 /app \
 && rm -rf /tmp/* /var/cache/apk/*

USER appuser
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/server.js"]

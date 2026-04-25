# ── Stage 1: Install dependencies ──────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app

RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# ── Stage 2: Production runtime ────────────────────────────────
FROM node:20-alpine AS production

RUN addgroup -g 1001 -S appgroup \
 && adduser  -u 1001 -S appuser -G appgroup \
 && apk add --no-cache dumb-init

WORKDIR /app

COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/package*.json ./
COPY --from=builder --chown=appuser:appgroup /app/server.js     ./server.js
COPY --from=builder --chown=appuser:appgroup /app/manage.js     ./manage.js
COPY --from=builder --chown=appuser:appgroup /app/src           ./src
COPY --from=builder --chown=appuser:appgroup /app/public        ./public

RUN mkdir -p /app/data \
 && chown -R appuser:appgroup /app/data \
 && rm -rf /tmp/* /var/cache/apk/*

USER appuser

ENV NODE_ENV=production
ENV PORT=3010
EXPOSE 3010

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.js"]

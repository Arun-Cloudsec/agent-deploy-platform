# ── Stage 1: Install dependencies ──────────────────────────────
# Pin to alpine3.20 specifically — `node:20-alpine` is mutable and may lag
# behind on patched OS packages. Re-pin to a newer release periodically
# (the runtime-image-scan workflow will catch drift).
FROM node:20-alpine3.20 AS builder

# Apply OS-level security patches that may have shipped since the base
# image was built. Cheap, deterministic, and prevents Trivy from flagging
# already-patched-upstream CVEs.
RUN apk update && apk upgrade --no-cache

WORKDIR /app

RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# ── Stage 2: Production runtime ────────────────────────────────
FROM node:20-alpine3.20 AS production

RUN apk update && apk upgrade --no-cache \
 && addgroup -g 1001 -S appgroup \
 && adduser  -u 1001 -S appuser -G appgroup \
 && apk add --no-cache dumb-init \
 # Remove npm + corepack from the production image. We don't invoke npm at
 # runtime (CMD is `node server.js`), and Node 20's bundled npm carries a
 # number of HIGH-severity vulns in its own transitive deps (cross-spawn,
 # glob, minimatch, tar — see Trivy scan). Deleting them eliminates all 11
 # findings without affecting runtime behavior. The builder stage still has
 # npm available for the `npm ci` step.
 && rm -rf /usr/local/lib/node_modules/npm \
           /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm \
           /usr/local/bin/npx \
           /usr/local/bin/corepack \
           /opt/yarn-*

WORKDIR /app

COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/package*.json ./
COPY --from=builder --chown=appuser:appgroup /app/server.js     ./server.js
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

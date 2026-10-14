# syntax=docker/dockerfile:1
FROM node:22.11-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22.11-alpine
ENV NODE_ENV=production PORT=3333
WORKDIR /app
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node package.json ./
# Runs as the unprivileged node user, never root.
USER node
EXPOSE 3333
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s CMD wget -qO- http://127.0.0.1:3333/healthz || exit 1
CMD ["node", "dist/http.js"]

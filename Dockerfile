FROM node:26-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG APP_VERSION
RUN if [ -n "$APP_VERSION" ]; then npm pkg set version="${APP_VERSION}.0"; fi && npm run build && npm prune --omit=dev

FROM node:26-alpine
ENV NODE_ENV=production HOST=0.0.0.0 SHELLPORT_CONFIG=/config/config.json
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --start-interval=1s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
CMD ["node", "dist/server.js"]

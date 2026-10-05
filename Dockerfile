# syntax=docker/dockerfile:1.7
#
# Stage 1 runs natively on the build host (amd64 in CI) and produces pure-JS output.
# Stage 2 runs once per target platform and only copies files, so the arm64 image
# never runs npm/pnpm under QEMU.

FROM --platform=$BUILDPLATFORM node:24.18-alpine AS build
RUN corepack enable
WORKDIR /src
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json .npmrc tsconfig.base.json ./
COPY packages/core/package.json packages/core/
COPY packages/server/package.json packages/server/
COPY packages/web/package.json packages/web/
COPY e2e/package.json e2e/
RUN pnpm install --frozen-lockfile
COPY . .
# Release builds pass the git tag here so the web bundle and the server's
# version report match each other and the CLI binaries.
ARG MIDDEN_VERSION=
RUN pnpm --filter @midden/core build \
 && pnpm --filter @midden/server build \
 && pnpm --filter @midden/web build \
 && pnpm --filter @midden/server deploy --legacy --prod --ignore-scripts /out/server \
 && sh scripts/check-no-native.sh /out/server/node_modules

FROM node:24.18-alpine AS runtime
ARG MIDDEN_VERSION=
ENV NODE_ENV=production \
    NODE_OPTIONS=--no-warnings=ExperimentalWarning \
    MIDDEN_DATA=/data \
    MIDDEN_PORT=8080 \
    MIDDEN_VERSION=$MIDDEN_VERSION
COPY --from=build /out/server /app
COPY --from=build /src/packages/web/dist /app/public
COPY docker/entrypoint.sh /app/entrypoint.sh
# Pull current Alpine security fixes (the published base tag lags the distro
# repo by days), then drop npm/corepack: the app never runs a package manager
# and the CLI's bundled deps (tar, pacote, ...) are pure attack surface.
RUN apk upgrade --no-cache \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /usr/local/bin/yarn /usr/local/bin/yarnpkg \
 && mkdir -p /data && chown node:node /data /app/entrypoint.sh && chmod +x /app/entrypoint.sh
USER node
WORKDIR /app
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:8080/api/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
ENTRYPOINT ["/app/entrypoint.sh"]

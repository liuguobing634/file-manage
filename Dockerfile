# 基础镜像：默认取 docker.io 的 node:22-alpine。
# 服务器无法访问 docker.io 时，三种改法（任选其一）：
#   1) 先在有网机器 docker save/load 到服务器，再原样构建（本地已有该镜像就不会联网拉取）；
#   2) 推送到内网 registry 后指定：
#      docker build --build-arg BASE_IMAGE=harbor.intranet/library/node:22-alpine -t file-manage:1.0.0 .
#   3) 使用自己 tag 好的本地镜像名。
ARG BASE_IMAGE=node:22-alpine

# ---------- 构建阶段：安装依赖 + TypeScript 编译 ----------
FROM ${BASE_IMAGE} AS builder
WORKDIR /app

# npm 源：内网可指向 Nexus / Verdaccio 等私有源
#   docker build --build-arg NPM_REGISTRY=https://registry.npmmirror.com -t file-manage:1.0.0 .
ARG NPM_REGISTRY=https://registry.npmjs.org

# 先复制依赖清单，充分利用镜像层缓存
COPY package.json package-lock.json* ./
RUN npm config set registry "$NPM_REGISTRY" \
    && (npm ci --no-audit --no-fund || npm install --no-audit --no-fund)

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build \
    && npm prune --omit=dev \
    && npm cache clean --force

# ---------- 运行阶段：仅保留运行时必需文件 ----------
ARG BASE_IMAGE=node:22-alpine
FROM ${BASE_IMAGE} AS runtime

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    DATA_DIR=/var/lib/file-manage \
    LOG_LEVEL=info \
    TZ=Asia/Shanghai

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./package.json
COPY public ./public

# 数据目录：保存 TOTP 密钥与审计日志（务必挂载为卷，否则容器重建后 TOTP 需重新绑定）
RUN mkdir -p /var/lib/file-manage && chown -R node:node /var/lib/file-manage /app
VOLUME ["/var/lib/file-manage"]

USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# 说明：Node 作为 PID 1 时已注册 SIGTERM/SIGINT 处理，收到 docker stop 会优雅退出
CMD ["node", "dist/server.js"]

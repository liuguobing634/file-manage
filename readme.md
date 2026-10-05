# file-manage · 服务器磁盘文件管理运维服务

面向服务器运维场景的**磁盘文件管理服务**：指定若干目录（可多选）后，可浏览、检索、下载、删除其中的文件；
所有接口都需要登录令牌，删除这类高危操作还必须额外提供 **TOTP 动态验证码**（二次验证）。
项目使用 Node.js + TypeScript 编写，可打包为单个 Docker 镜像交付。

> 对应需求：① 多选目录下的文件读取 / 下载 / 删除；② 启动时指定账号密码，登录换取 token，其余接口在请求头带 token；
> ③ 删除需要 TOTP 二次验证，二维码只能生成一次，**重置只能通过命令行**（不提供 API）。

---

## 目录

- [功能特性](#功能特性)
- [目录结构](#目录结构)
- [快速开始](#快速开始)
- [使用流程](#使用流程)
- [内网 / 无法访问 docker.io 的部署](#内网--无法访问-dockerio-的部署)
- [内置 Web 控制台](#内置-web-控制台)
- [环境变量](#环境变量)
- [TOTP 重置（命令行，无 API）](#totp-重置命令行无-api)
- [API 一览](#api-一览)
- [安全设计](#安全设计)
- [开发与测试](#开发与测试)
- [常见问题](#常见问题)
  - [挂载目录不可读 / 不可写（权限问题）](#挂载目录不可读--不可写权限问题)
  - [ALLOWED_ROOTS 写了宿主机路径 / 目录列表为空](#allowed_roots-写了宿主机路径--目录列表为空)

---

## 功能特性

| 能力 | 说明 |
| --- | --- |
| 多目录管理 | `ALLOWED_ROOTS=/data,/srv/logs` 启动时指定多个目录，接口中可用 `"@roots"` 表示全部 |
| 浏览与检索 | 目录浏览（含容量/剩余空间）、多目录递归列举，支持扩展名、文件名、大小区间过滤与数量上限 |
| 下载 | 单文件断点续传下载；多选（或多个目录）自动流式打包为 zip，中文文件名正常 |
| 删除 | 支持单文件 / 目录（递归），逐条返回成功与失败原因；**必须携带 TOTP 验证码** |
| 登录鉴权 | 启动时指定账号密码（或 scrypt 哈希），`POST /api/auth/login` 换取 JWT，其余接口在请求头携带 |
| TOTP 二次验证 | 标准 TOTP（RFC 6238，SHA1/SHA256/SHA512，默认 6 位 30 秒），二维码只能生成一次，重置仅限命令行 |
| 安全防护 | 路径白名单 + 软链接逃逸检测、登录/验证码限流、验证码防重放、常量时间比较、审计日志 |
| 内置控制台 | 免安装的 Web 控制台（`public/index.html`），登录、浏览、下载、删除、TOTP 绑定一体化 |
| 交付形态 | 多阶段构建的 Docker 镜像，非 root 运行，带 HEALTHCHECK；支持 docker compose 一键部署 |

---

## 目录结构

```
file-manage/
├── src/
│   ├── server.ts            # 进程入口：加载配置、启动监听、优雅退出
│   ├── app.ts               # Express 应用装配（安全响应头、路由、错误处理）
│   ├── config.ts            # 环境变量解析与校验（含 .env 读取）
│   ├── context.ts           # 运行时依赖装配（server 与测试共用）
│   ├── logger.ts            # JSON 结构化日志（敏感字段脱敏）
│   ├── errors.ts            # 统一错误类型与错误码
│   ├── version.ts
│   ├── middleware/          # 鉴权、限流、错误处理
│   ├── routes/              # auth / files / totp / system
│   ├── services/            # TOTP、密码、路径守卫、文件操作、zip、审计、令牌、状态存储
│   ├── cli/                 # 命令行：totp 状态与重置、生成密码哈希
│   └── types/               # Express 类型扩展
├── public/index.html        # 内置 Web 控制台（无构建、无外部依赖）
├── test/                    # node:test 测试（TOTP RFC 向量、路径守卫、配置、HTTP 接口）
├── scripts/smoke.mjs        # 针对构建产物的端到端冒烟测试
├── docs/API.md              # 完整 API 契约
├── Dockerfile               # 多阶段构建
├── docker-compose.yml        # 一键构建 + 运行（本地 / 能构建的机器）
├── docker-compose.server.yml # 仅运行：服务器 docker load 后 up -d，无 build 段
└── .env.example             # 环境变量样例
```

---

## 快速开始

### 方式一：Docker Compose（推荐）

```bash
cp .env.example .env
# 编辑 .env，至少修改 ADMIN_PASSWORD、JWT_SECRET、ALLOWED_ROOTS
# compose 会读取同目录的 .env，并把 ./data 挂载为容器内 /data
docker compose up -d --build
docker compose logs -f file-manage
```

浏览器访问 `http://<服务器IP>:3000`，用 `ADMIN_USERNAME / ADMIN_PASSWORD` 登录。

> 已经在本地构建好镜像、服务器只负责运行（服务器无法访问 docker.io）时，
> 用 `docker-compose.server.yml`：`docker load -i file-manage-1.0.0.tar` 后
> `docker compose -f docker-compose.server.yml up -d`，
> 详见[方案 A2](#方案-a2本地已构建好镜像服务器只执行-docker-compose-up--d)。

### 方式二：docker run

```bash
docker build -t file-manage:1.0.0 .
# 国内网络可加：--build-arg NPM_REGISTRY=https://registry.npmmirror.com

docker volume create file-manage-state
docker run -d --name file-manage --restart unless-stopped \
  -p 3000:3000 \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD='请改成强密码' \
  -e JWT_SECRET='请改成 32 位以上随机串' \
  -e ALLOWED_ROOTS=/data,/logs \
  -v /host/appdata:/data \
  -v /var/log:/logs:ro \
  -v file-manage-state:/var/lib/file-manage \
  file-manage:1.0.0
```

> `-v file-manage-state:/var/lib/file-manage` 用于保存 TOTP 密钥与审计日志。**不挂载的话容器重建后 TOTP 需要重新绑定。**

容器内重置 TOTP（唯一的重置方式）：

```bash
docker exec -it file-manage node dist/cli/totp.js status
docker exec -it file-manage node dist/cli/totp.js reset
```

### 方式三：本地 Node 运行

要求 Node.js ≥ 20.11。

```bash
npm install
cp .env.example .env        # 修改 ADMIN_PASSWORD / JWT_SECRET / ALLOWED_ROOTS
npm run dev                 # 开发模式（tsx watch，自动读取 .env）
# 或生产模式：
npm run build && npm start
```

---

## 使用流程

```bash
BASE=http://127.0.0.1:3000

# 1) 登录，换取 token
TOKEN=$(curl -s -X POST $BASE/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"你的密码"}' | jq -r .token)

# 2) 查看允许管理的目录（多选）
curl -s $BASE/api/roots -H "Authorization: Bearer $TOKEN"

# 3) 浏览 / 递归列举
curl -s "$BASE/api/browse?path=/data" -H "Authorization: Bearer $TOKEN"
curl -s -X POST $BASE/api/files/list -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"paths":["@roots"],"recursive":true,"extensions":[".log"],"minSize":1024}'

# 4) 下载
curl -sO -J "$BASE/api/files/download?path=/data/app.log" -H "Authorization: Bearer $TOKEN"
curl -s -X POST $BASE/api/files/download -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"paths":["/data/logs","/data/tmp"]}' -o files.zip

# 5) 绑定 TOTP：生成密钥 + 二维码（只能生成一次）
curl -s -X POST $BASE/api/totp/setup -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{}'
#    → 返回 secret / otpauthUrl / qrCodeDataUrl，用 Google Authenticator 等扫码

# 6) 扫码后用当前验证码激活
curl -s -X POST $BASE/api/totp/verify -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"code":"123456"}'

# 7) 删除（高危操作，必须带 totp 验证码）
curl -s -X POST $BASE/api/files/delete -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"paths":["/data/app.log"],"totp":"654321"}'
```

要点：

- `POST /api/totp/setup` **只能成功一次**；密钥已存在时返回 `409 TOTP_ALREADY_CONFIGURED`。
- 未完成 `verify` 激活时，删除接口返回 `403 TOTP_NOT_ENABLED`。
- 默认开启防重放：**同一个验证码只能使用一次**（同一 30 秒窗口内不能连续删两次）。
  确需连续操作可设置 `TOTP_PREVENT_REPLAY=false`，或等下一个验证码周期。
- 附带 `?token=<jwt>` 的写法**仅**对 `GET /api/files/download` 与 `GET /api/totp/qrcode` 有效，方便浏览器直接打开。

---

## 内网 / 无法访问 docker.io 的部署

先分清两件事：

| 构建时需要的网络 | 用途 | 能否替换 |
| --- | --- | --- |
| **docker.io**（Docker Hub） | 拉取基础镜像 `node:22-alpine` | ✅ 换成内网 registry，或提前 `docker load` 到服务器 |
| **npm 源**（默认 `registry.npmjs.org`） | 安装 express / typescript 等依赖 | ✅ `--build-arg NPM_REGISTRY=...` 换成内网 Nexus / Verdaccio / npmmirror |

只要基础镜像与 npm 依赖能在本地或内网拿到，**服务器就完全不需要访问 docker.io**。

### 方案 A（最省事）：在能上网的机器上构建，导出镜像到服务器运行

服务器只负责运行，不需要源码、Node、npm：

```bash
# ① 联网机器（Linux / macOS）
docker build --build-arg NPM_REGISTRY=https://registry.npmmirror.com -t file-manage:1.0.0 .
docker save file-manage:1.0.0 | gzip -9 > file-manage-1.0.0.tar.gz
scp file-manage-1.0.0.tar.gz root@10.0.0.8:/root/

# ② 服务器（无外网）
gunzip -c file-manage-1.0.0.tar.gz | docker load
docker volume create file-manage-state
docker run -d --name file-manage --restart unless-stopped -p 3000:3000 \
  -e ADMIN_USERNAME=admin -e ADMIN_PASSWORD='改成强密码' \
  -e JWT_SECRET='32位以上随机串' -e ALLOWED_ROOTS=/data \
  -v /hostdir:/data -v file-manage-state:/var/lib/file-manage \
  file-manage:1.0.0
```

Windows（本机）导出：

```powershell
docker build --build-arg NPM_REGISTRY=https://registry.npmmirror.com -t file-manage:1.0.0 .
docker save file-manage:1.0.0 -o file-manage-1.0.0.tar     # 约 200 MB，可再压缩后传输
# 传到服务器后：
docker load -i file-manage-1.0.0.tar
```

> 镜像已包含全部运行时依赖，服务器上不需要 Node/npm/源码。
> 仍然要挂载状态卷（`/var/lib/file-manage`），否则容器重建后 TOTP 需重新绑定。

### 方案 A2：本地已构建好镜像，服务器只执行 `docker compose up -d`

可以，两种情况都实测过：

| 服务器上用的 compose 文件 | 实际行为 |
| --- | --- |
| `docker-compose.server.yml`（**没有 build 段**） | 直接用本地镜像启动；服务器上不需要源码、Dockerfile、Node、npm |
| `docker-compose.yml`（带 build 段） | 只要 `image:` 指定的镜像**本地已存在**，`up -d` **不会重新构建**，直接用它启动 |

但有几个必须对上的点，否则 compose 会去 docker.io 拉取而失败：

1. **镜像名与标签必须和 compose 里的 `image:` 完全一致**（默认 `file-manage:1.0.0`）。
   本地构建时就用 `docker build -t file-manage:1.0.0 .`，或者 `docker tag <你的名字> file-manage:1.0.0`。
2. 服务器上要有 `.env`（被 `.gitignore` 忽略，需要手动拷过去）和 compose 文件本身。
3. **不要加 `--build`**；想彻底防呆就用 `docker compose up -d --no-build`。
4. 不要执行 `docker compose pull`（那会去 registry 拉取）。

服务器目录最简形态（只有三个东西）：

```
/opt/file-manage/
├── docker-compose.server.yml
├── .env
└── data/                 # 被管理的目录，按需
```

```bash
docker load -i file-manage-1.0.0.tar
cd /opt/file-manage
docker compose -f docker-compose.server.yml up -d
docker compose -f docker-compose.server.yml logs -f
```

如果服务器能连内网 registry，用镜像名拉取更省事：

```bash
# 本地
docker tag file-manage:1.0.0 harbor.intranet/tools/file-manage:1.0.0
docker push harbor.intranet/tools/file-manage:1.0.0
# 服务器 .env 里写 IMAGE=harbor.intranet/tools/file-manage:1.0.0，然后
docker compose -f docker-compose.server.yml pull
docker compose -f docker-compose.server.yml up -d
```

### 方案 B：必须在服务器上构建

需要分别解决「基础镜像」和「npm 依赖」。

**B1. 让服务器拿到基础镜像（三选一）**

```bash
# 方式 1：从内网 registry 拉（有 Harbor 时最推荐）
docker pull harbor.intranet/library/node:22-alpine
docker build --build-arg BASE_IMAGE=harbor.intranet/library/node:22-alpine -t file-manage:1.0.0 .

# 方式 2：从联网机器 save/load 基础镜像（约 167 MB）
#   联网机器：
docker pull node:22-alpine
docker save node:22-alpine -o node-22-alpine.tar
#   服务器：
docker load -i node-22-alpine.tar
docker build -t file-manage:1.0.0 .          # 本地已有该镜像，不会再去 docker.io

# 方式 3：把基础镜像推到内网 registry，再在服务器构建
docker tag node:22-alpine harbor.intranet/library/node:22-alpine
docker push harbor.intranet/library/node:22-alpine
#   服务器：
docker build --build-arg BASE_IMAGE=harbor.intranet/library/node:22-alpine -t file-manage:1.0.0 .
```

> 关键点：**`FROM` 用到的镜像只要本地已存在，`docker build` 就不会去 registry 拉取**。
> 所以服务器上已有 `node:22-alpine` 时，直接 `docker build` 即可，无需任何外网。
> 若镜像在别的名字下（例如从别处 load 进来的），`docker tag 原名 node:22-alpine`
> 或者 `--build-arg BASE_IMAGE=<原名>` 都可以。

**B2. 让服务器拿到 npm 依赖（三选一）**

```bash
# ① 内网私有源（Nexus / Verdaccio / 公司镜像）
docker build --build-arg NPM_REGISTRY=http://nexus.intranet/repository/npm-group/ -t file-manage:1.0.0 .

# ② 走 HTTP 代理出网（BuildKit 会自动识别这两个构建参数）
docker build --build-arg HTTP_PROXY=http://proxy.intranet:3128 \
             --build-arg HTTPS_PROXY=http://proxy.intranet:3128 \
             --build-arg NPM_REGISTRY=https://registry.npmmirror.com -t file-manage:1.0.0 .

# ③ 使用国内公共源
docker build --build-arg NPM_REGISTRY=https://registry.npmmirror.com -t file-manage:1.0.0 .
```

用 docker compose 时把参数写进 `.env` 即可（compose 会自动读取）：

```dotenv
BASE_IMAGE=harbor.intranet/library/node:22-alpine
NPM_REGISTRY=http://nexus.intranet/repository/npm-group/
```

### 方案 C：服务器能出网、只是 docker.io 被墙 —— 配置镜像加速

```bash
sudo tee /etc/docker/daemon.json >/dev/null <<'JSON'
{
  "registry-mirrors": ["https://<可用的加速地址>"],
  "insecure-registries": ["harbor.intranet:5000"]
}
JSON
sudo systemctl daemon-reload && sudo systemctl restart docker
```

注意：2024 年之后多数公共加速地址已失效或限流，长期可靠的做法是**自建 Harbor**，
或使用云厂商容器镜像服务提供的专属加速地址。`insecure-registries` 仅用于 HTTP 或自签证书的内网 registry。

### 方案 D：完全不用 Docker

服务本身就是一个普通 Node 程序，服务器有内网 npm 源时可以直接跑：

```bash
npm ci --registry=http://nexus.intranet/repository/npm-group/
npm run build
ADMIN_USERNAME=admin ADMIN_PASSWORD='强密码' JWT_SECRET='32位以上随机串' \
ALLOWED_ROOTS=/data,/logs DATA_DIR=/var/lib/file-manage node dist/server.js
```

systemd 守护（`/etc/systemd/system/file-manage.service`）：

```ini
[Unit]
Description=file-manage 磁盘文件管理服务
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/file-manage
EnvironmentFile=/opt/file-manage/.env
ExecStart=/usr/bin/node dist/server.js
Restart=always
User=filemanage

[Install]
WantedBy=multi-user.target
```

> 以非 root 用户运行时，被管理目录需要相应的读/写权限（删除操作需要目录的写权限）。

### 部署后验证

在任意有 Node 的机器上（指向服务器地址即可，无需在被验证的机器上装 Node）：

```bash
SMOKE_BASE_URL=http://10.0.0.8:3000 \
SMOKE_PASSWORD='你的密码' \
SMOKE_MANAGED_DIR=/hostdir SMOKE_CONTAINER_DIR=/data \
node scripts/smoke-docker.mjs
```

---

## 内置 Web 控制台

服务启动后访问 `http://<地址>:3000/` 即可使用内置控制台（单文件、零依赖）：

- 登录 / 退出、登录状态与 TOTP 徽标
- 授权目录卡片（含总容量、剩余空间、已用比例）
- 目录浏览、面包屑、上一级、多选（文件与目录均可勾选）
- 递归检索（扩展名 / 关键字 / 大小区间）与结果排序
- 单个下载、多选打包 zip 下载
- 删除确认弹窗（列出待删路径、输入 6 位验证码、可选递归）
- TOTP 面板：生成二维码 → 扫码 → 激活；已启用时提示重置只能走命令行

如需关闭控制台（只保留 API），设置 `SERVE_STATIC=false`。

---

## 环境变量

| 变量 | 默认值 | 必填 | 说明 |
| --- | --- | --- | --- |
| `ADMIN_USERNAME` | `admin` | | 登录账号 |
| `ADMIN_PASSWORD` | — | 二选一 | 登录密码（明文，来自环境变量） |
| `ADMIN_PASSWORD_HASH` | — | 二选一 | scrypt 哈希，优先级高于 `ADMIN_PASSWORD`；用 `npm run hash-password -- '密码'` 生成 |
| `JWT_SECRET` | 随机生成 | 建议 | 令牌签名密钥；不设置会随机生成并告警（重启后所有 token 失效） |
| `JWT_TTL_SECONDS` | `7200` | | 令牌有效期（秒） |
| `ALLOWED_ROOTS` | — | ✔ | 允许管理的目录，逗号/分号分隔的**绝对路径**（可多选） |
| `HOST` / `PORT` | `0.0.0.0` / `3000` | | 监听地址与端口 |
| `TRUST_PROXY` | `false` | | 置于反向代理之后时设为 `true`（限流按真实 IP 统计） |
| `LOG_LEVEL` | `info` | | `debug` / `info` / `warn` / `error` |
| `SERVE_STATIC` | `true` | | 是否提供内置 Web 控制台 |
| `DATA_DIR` | `./data` | | TOTP 密钥与审计日志目录（**务必持久化**） |
| `MAX_LIST_FILES` | `5000` | | 单次列举返回的最大条目数 |
| `MAX_LIST_DEPTH` | `16` | | 递归列举的最大深度 |
| `MAX_DELETE_PATHS` | `1000` | | 单次删除的路径数量上限 |
| `MAX_ZIP_FILES` | `20000` | | 单次打包下载的文件数量上限 |
| `LOGIN_RATE_WINDOW_SECONDS` / `LOGIN_RATE_MAX_ATTEMPTS` | `600` / `10` | | 登录失败限流窗口与次数 |
| `TOTP_RATE_WINDOW_SECONDS` / `TOTP_RATE_MAX_ATTEMPTS` | `60` / `10` | | 二次验证失败限流窗口与次数 |
| `TOTP_ISSUER` | `file-manage` | | 验证器 App 中显示的名称 |
| `TOTP_DIGITS` / `TOTP_PERIOD` / `TOTP_ALGORITHM` | `6` / `30` / `SHA1` | | 验证码位数、周期（秒）、算法；**仅在 setup 时生效**，见下方说明 |
| `TOTP_WINDOW` | `1` | | 允许的时间漂移（±N 个周期） |
| `TOTP_PREVENT_REPLAY` | `true` | | 同一验证码是否只能使用一次 |

> **关于 `TOTP_DIGITS` / `TOTP_PERIOD` / `TOTP_ALGORITHM` 的生效时机**：
> 这三个参数（以及 `TOTP_ISSUER`）会在 `POST /api/totp/setup` 生成二维码时**冻结保存**进状态文件，
> 之后校验一律使用绑定时的参数。这样做是为了避免「改了环境变量 → 已绑定的验证器全部失效」这种事故。
> 已绑定后若修改了这些环境变量，`GET /api/totp/status` 会返回 `"paramsChanged": true` 提示你：
> 新参数**不会**自动生效，要切换必须 `node dist/cli/totp.js reset` 后重新扫码绑定。

---

## TOTP 重置（命令行，无 API）

按要求，**TOTP 的重置不提供任何 HTTP 接口**，只能在服务器上执行命令：

```bash
npm run totp:status                     # 或 node dist/cli/totp.js status
npm run totp:reset                      # 清除密钥，之后可重新 setup
node dist/cli/totp.js reset --dry-run   # 只显示将要重置的内容

# Docker
docker exec -it file-manage node dist/cli/totp.js reset
```

重置后重新登录控制台，调用 `POST /api/totp/setup` 生成新二维码即可。

> 重置**立即生效，无需重启服务**：服务端每次读写都会校验状态文件的指纹，
> 命令行（另一个进程）删除文件后，正在运行的服务会立刻感知并恢复正常态。
>
> 若只想查看状态而不改密钥，用 `status`；状态文件位于 `$DATA_DIR/totp.json`（权限 600），
> 删除它同样等价于重置。**请勿在服务运行时手工编辑该文件。**

---

## API 一览

完整请求/响应示例、字段说明与错误码见 **[docs/API.md](docs/API.md)**。

| 方法 | 路径 | 认证 | 说明 |
| --- | --- | --- | --- |
| `POST` | `/api/auth/login` | — | 账号密码登录，返回 token |
| `GET` | `/api/auth/me` | ✔ | 当前登录信息与 TOTP 状态 |
| `POST` | `/api/auth/logout` | ✔ | 注销当前令牌（jti 拉黑） |
| `GET` | `/api/roots` | ✔ | 授权目录列表（含容量信息） |
| `GET` | `/api/browse` | ✔ | 浏览单个目录 |
| `POST` | `/api/files/list` | ✔ | 多目录（可递归）列举文件 |
| `GET` | `/api/files` | ✔ | 单路径列举（便捷写法） |
| `GET` | `/api/files/download` | ✔（支持 `?token=`） | 下载单个文件 |
| `POST` | `/api/files/download` | ✔ | 多选打包 zip 下载 |
| `POST` | `/api/files/delete`（或 `DELETE /api/files`） | ✔ + **TOTP** | 删除文件 / 目录（高危） |
| `GET` | `/api/totp/status` | ✔ | TOTP 绑定状态 |
| `POST` | `/api/totp/setup` | ✔ | 生成密钥与二维码（**仅一次**） |
| `GET` | `/api/totp/qrcode` | ✔（支持 `?token=`） | 当前密钥的二维码 PNG |
| `POST` | `/api/totp/verify` | ✔ | 用验证码激活 TOTP |
| `GET` | `/healthz` | — | 存活探针 |

---

## 安全设计

**路径安全**
- 只允许 `ALLOWED_ROOTS` 下的绝对路径，相对路径一律 400。
- 先做字符串规范化，再用 `realpath` 解析软链接，**解析后仍必须位于授权目录内**，否则 403（防软链接逃逸）。
- 列举时跳过指向授权目录之外的软链接；不跟随软链接目录递归，避免环路与越权。
- `DATA_DIR`（TOTP 密钥、审计日志）对外完全不可见，无法浏览、下载或删除。
- 禁止删除被授权的根目录本身。

**认证与授权**
- 密码支持 scrypt 哈希（`ADMIN_PASSWORD_HASH`）；明文比较也使用常量时间实现，避免时序侧信道。
- JWT（HS256，固定 issuer），支持 `Authorization: Bearer` 与 `X-Auth-Token`；`POST /api/auth/logout` 通过 jti 拉黑。
- 登录失败按「IP + 账号」限流（默认 10 次 / 10 分钟），返回 `429` 并带 `Retry-After`；登录成功清零。

**高危操作**
- 删除必须同时满足：已登录 + TOTP 已激活 + 验证码正确 + 未被重放，缺一返回 400/403。
- 二次验证失败同样限流；验证码比较为常量时间且只接受纯数字定长输入。
- 校验通过后验证码立即作废（默认 `TOTP_PREVENT_REPLAY=true`）。

**其它**
- 所有请求带 `X-Request-Id`；响应含 `nosniff`、`no-referrer`、`X-Frame-Options: DENY` 与 CSP。
- 审计日志（JSON Lines，`$DATA_DIR/audit.log`）记录登录成功/失败、注销、列举、浏览、下载、删除、TOTP 生成与激活。
- 容器以非 root 的 `node` 用户运行；日志对密码 / token / 验证码等字段自动脱敏。

---

## 开发与测试

```bash
npm run typecheck     # 类型检查（src + test）
npm run build         # 编译到 dist/
npm test              # 单元 + 接口测试（99 项，含 TOTP RFC 向量与路径逃逸用例）
npm run smoke         # 先 npm run build，再用 dist 产物跑一遍端到端链路
node scripts/smoke-docker.mjs   # 对已运行的容器/实例做冒烟（见文件头的环境变量说明）
npm run hash-password -- '你的密码'   # 生成 ADMIN_PASSWORD_HASH
npm run doctor        # 环境体检：进程 uid、数据目录可写性、各授权目录的属主/权限/R-W-X 与修复命令
```

测试覆盖要点：

- **TOTP**：Base32 编解码、RFC 4226 附录 D 的 HOTP 向量、RFC 6238 附录 B 的 SHA1/SHA256/SHA512 向量、
  时间漂移窗口、`minStepExclusive` 防重放、otpauth URL，以及「命令行重置后服务端立即感知」的跨进程场景。
- **路径守卫**：越权目录、`../` 穿越、相似前缀兄弟目录、目录链接（Windows 回退 junction）逃逸、
  指向内部的软链接、断链软链接、数据目录隔离、根目录删除保护。
- **接口**：登录成功/失败/限流、令牌缺失/无效/已注销、浏览与列举过滤、单文件与 zip 下载（自实现 ZIP 解析校验内容）、
  删除的 400/403/重放/根目录保护/非空目录/越界路径、审计日志落盘、scrypt 哈希登录。
- **配置**：必填项缺失、非法数值、相对路径、无效目录跳过、临时 `JWT_SECRET` 告警、`.env` 解析。

---

## 常见问题

### 挂载目录不可读 / 不可写（权限问题）

**症状**：登录后控制台里根目录卡片标红「不可读 / 无进入权限(x) / 不可写」；
或浏览时报 `403 PERMISSION_DENIED 没有权限读取目录: /data/backups`；
或删除失败；或容器起不来并提示 `无法写入数据目录 /var/lib/file-manage`。

**原因**：镜像里的进程是**非 root 的 `node` 用户（uid=1000, gid=1000）**，
而宿主机上被挂载的目录通常属于 `root`（常见权限 `700` / `750` / `755` 但 other 无 `x`）。
容器进程对它的权限，取决于**宿主目录的属主 + 权限位**，跟你宿主机上用 root 能不能看没关系。

先跑一条体检命令看个明白：

```bash
docker exec -it file-manage node dist/cli/doctor.js
# 或本地：npm run build && npm run doctor
```

它会打印进程身份、每个授权目录的「属主 / 权限位 / R-W-X」，以及针对性的修复命令（有阻塞问题时退出码为 1）。
例如：

```
进程身份   : uid=1000(node) gid=1000
     /data/backups  属主=0:0 权限=700 R=n W=n X=n
FAIL /data/backups: 缺少进入(x)权限，无法列出内容（属主 0:0 权限 700）
```

**修复（任选一种）**：

```bash
# ① 让宿主目录归属容器用户（最直接）
sudo chown -R 1000:1000 /data/backups /data/backup-db

# ② 只想放开读取，不改属主
sudo chmod -R o+rX /data/backups /data/backup-db      # 需要删除则还要给写权限
sudo setfacl -R -m u:1000:rwX /data/backups           # 不想动 other 权限时用 ACL

# ③ SELinux 系统（RHEL / CentOS / Rocky / AlmaLinux）还需要标记挂载：
#    compose 里写成  - /data/backups:/data/backups:z     （多容器共享）或 :Z（独占）
#    验证：getenforce；临时排查可 setenforce 0 看是否恢复

# ④ 图省事：让容器以 root 运行（放弃非 root 加固，功能立刻可用）
#    在 compose 的服务里加一行：
#    user: "0:0"
#    或只补一个组（宿主目录是 root:root 且组有权限时）：
#    group_add: ["0"]
```

> 判定规则很简单：**容器里 uid 1000 能不能读，就等于宿主上 uid 1000 能不能读**。
> 快速验证：`docker exec -it file-manage ls -ln /data/backups`

**关于状态目录**：`/var/lib/file-manage` 用**命名卷**最省心（Docker 会把属主初始化成容器用户）；
如果 bind mount 到宿主目录（例如 `- /data/file-manage-state:/var/lib/file-manage`），
而该宿主目录属于 root，容器用户写不进去 → 现在会**直接启动失败并打印修复命令**（不再表现为「TOTP 绑定 500」）。

### ALLOWED_ROOTS 写了宿主机路径 / 目录列表为空

`ALLOWED_ROOTS` 必须写 **容器内路径**。对照关系：

```yaml
volumes:
  - /data/backups:/data/backups      # 宿主 /data/backups  →  容器 /data/backups
  - /data/backup-db:/data/backup-db
```

- 此时 `ALLOWED_ROOTS` 写 `/data/backups,/data/backup-db`，或直接写 `/data`（Docker 会自动创建该父目录并可进入）。
- 写成宿主机的其它路径（容器里不存在）会在启动时被**跳过**，日志里有 `已跳过不可用的授权目录` 告警，界面上就看不到它。
- 只挂了两个子目录、`ALLOWED_ROOTS=/data` 时，`/data` 只是一个空壳目录，里面能看到这两个子目录 —— 这是正常的。

排查：`docker compose logs file-manage | grep 跳过`，或看 `GET /api/system/info` 里的 `skippedRoots` / `rootProblems`。

---

**Q：忘记密码怎么办？**
改环境变量 `ADMIN_PASSWORD`（或 `ADMIN_PASSWORD_HASH`）后重启服务即可，无需数据库。

**Q：换了手机 / 验证器丢了？**
在服务器上执行 `node dist/cli/totp.js reset`（Docker：`docker exec -it file-manage node dist/cli/totp.js reset`），
重新登录并调用 `POST /api/totp/setup` 生成新二维码。**没有 HTTP 重置接口，这是有意为之。**

**Q：改了 `TOTP_ALGORITHM`（比如换成 SHA256），验证码一直提示错误？**
绑定参数在 `setup` 时就冻结了，改环境变量不会影响已绑定的验证器（`/api/totp/status` 会返回 `paramsChanged: true`）。
想让新算法生效：先 `node dist/cli/totp.js reset`，再用新验证器扫码绑定。
反之，如果你是在**重新绑定之后**才改的算法，那手机里旧的条目就作废了，删掉重新扫一次即可。
另外注意：验证器 App 必须支持所选算法（Google Authenticator / Microsoft Authenticator / 1Password 都支持 SHA256，但个别老 App 只支持 SHA1）。

**Q：删除时提示“验证码无效或已被使用”？**
默认防重放，同一验证码只能使用一次。请使用验证器当前的验证码；需要连续删除时等下一个 30 秒周期，
或设置 `TOTP_PREVENT_REPLAY=false`。

**Q：提示“路径不在授权目录内”？**
路径必须是 `ALLOWED_ROOTS` 中目录或其子目录的**绝对路径**。Docker 场景注意是**容器内路径**（如 `/data`），
不是宿主机路径。另外软链接若指向授权目录之外也会被拒绝。

**Q：容器重启后要重新绑定 TOTP？**
说明 `/var/lib/file-manage` 没有持久化，请挂载卷（compose 中已默认挂载 `file-manage-state`）。

**Q：为什么列表里有些软链接看不到？**
指向授权目录之外的软链接会被主动隐藏；指向目录内部的软链接正常显示，但递归列举时不会跟随进入。

**Q：一个实例能管多少目录？**
`ALLOWED_ROOTS` 中写多少个都行，接口里用 `"paths":["@roots"]` 即可一次列举全部。

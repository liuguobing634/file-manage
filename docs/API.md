# file-manage API 契约（v1）

所有接口以 `/api` 为前缀。除 `/healthz`、`/api/auth/login`、静态资源外，其余接口都需要携带访问令牌。

## 认证方式

登录成功后返回 JWT。请求时三选一：

| 方式 | 示例 |
| --- | --- |
| Authorization 头（推荐） | `Authorization: Bearer <token>` |
| 自定义头 | `X-Auth-Token: <token>` |
| 查询参数（**仅** `GET /api/files/download`、`GET /api/totp/qrcode` 支持，方便浏览器 `<a>` / `<img>` 直接访问） | `?token=<token>` |

## 统一错误格式

```json
{ "error": { "code": "TOKEN_INVALID", "message": "登录状态无效或已过期", "details": null }, "requestId": "..." }
```

常见错误码：

| HTTP | code | 说明 |
| --- | --- | --- |
| 400 | `BAD_REQUEST` / `INVALID_JSON` | 参数错误 |
| 401 | `TOKEN_MISSING` / `TOKEN_INVALID` / `TOKEN_REVOKED` | 未登录 / 令牌无效 / 已登出 |
| 401 | `INVALID_CREDENTIALS` | 账号或密码错误 |
| 403 | `PATH_NOT_ALLOWED` | 路径不在 `ALLOWED_ROOTS` 内（含软链接逃逸） |
| 403 | `TOTP_NOT_ENABLED` | 未完成 TOTP 绑定，禁止高危操作 |
| 403 | `TOTP_INVALID` | 二次验证码错误 / 已使用 |
| 403 | `ROOT_DELETE_FORBIDDEN` | 不允许删除被授权的根目录本身 |
| 404 | `NOT_FOUND` | 文件或目录不存在 |
| 409 | `TOTP_ALREADY_CONFIGURED` | TOTP 已生成，不能重复生成，只能重置 |
| 409 | `TOTP_ALREADY_ENABLED` | TOTP 已启用 |
| 409 | `TOTP_NOT_CONFIGURED` | 尚未生成 TOTP 密钥 |
| 409 | `DIRECTORY_NOT_EMPTY` | 目录非空且未开启递归删除 |
| 413 | `PAYLOAD_TOO_LARGE` | 请求体过大 |
| 429 | `RATE_LIMITED` | 触发频率限制（响应头带 `Retry-After`，单位秒） |
| 500 | `INTERNAL_ERROR` | 服务端错误 |

---

## 1. 登录与令牌

### POST /api/auth/login

无需认证。频率限制：`LOGIN_RATE_WINDOW_SECONDS` 窗口内最多 `LOGIN_RATE_MAX_ATTEMPTS` 次失败尝试（按 IP + 账号）。

请求：

```json
{ "username": "admin", "password": "change-me-please" }
```

响应 `200`：

```json
{ "token": "<jwt>", "tokenType": "Bearer", "expiresIn": 7200, "username": "admin" }
```

### GET /api/auth/me

响应 `200`：

```json
{
  "username": "admin",
  "issuedAt": "2024-05-01T10:00:00.000Z",
  "expiresAt": "2024-05-01T12:00:00.000Z",
  "totp": { "configured": true, "enabled": true }
}
```

### POST /api/auth/logout

注销当前令牌（服务端按 `jti` 撤销）。响应 `200`：`{ "ok": true }`

---

## 2. 目录与文件

### GET /api/roots

返回启动时通过 `ALLOWED_ROOTS` 指定的可管理目录（多选）。

```json
{
  "roots": [
    { "id": "r0", "path": "/data", "exists": true, "readable": true, "totalBytes": 10737418240, "freeBytes": 5368709120 }
  ]
}
```

### GET /api/browse?path=/data&showHidden=false

浏览**单个**目录的直接子项；不带 `path` 时等价于返回根目录列表。

```json
{
  "path": "/data",
  "root": "/data",
  "parent": null,
  "count": 2,
  "truncated": false,
  "entries": [
    { "name": "app.log", "path": "/data/app.log", "type": "file", "size": 1024, "mtime": "2024-05-01T10:00:00.000Z", "mode": "644", "ext": ".log", "isSymlink": false },
    { "name": "archive", "path": "/data/archive", "type": "dir", "size": 0, "mtime": "2024-05-01T09:00:00.000Z", "mode": "755", "ext": "", "isSymlink": false }
  ]
}
```

### POST /api/files/list

多目录（多选）递归/非递归列举文件。`paths` 中可用魔法值 `"@roots"` 表示全部授权根目录。

请求：

```json
{
  "paths": ["/data", "/srv/logs"],
  "recursive": true,
  "maxDepth": 0,
  "includeDirs": false,
  "showHidden": false,
  "extensions": [".log", ".gz"],
  "nameContains": "error",
  "minSize": 0,
  "maxSize": 0,
  "limit": 5000
}
```

字段说明：`maxDepth` 为 `0` 表示不限（内部受 `MAX_LIST_DEPTH` 保护）；`extensions` 大小写不敏感，前缀 `.` 可省略；`minSize`/`maxSize` 单位字节，`0` 表示不限。

另提供等价的 `GET /api/files?path=/data&recursive=true&extensions=.log`（只支持单路径）。

响应 `200`：

```json
{
  "count": 2,
  "totalSize": 2048,
  "scanned": 15,
  "truncated": false,
  "files": [
    { "path": "/data/app.log", "name": "app.log", "type": "file", "size": 1024, "mtime": "2024-05-01T10:00:00.000Z", "root": "/data", "relPath": "app.log", "ext": ".log", "isSymlink": false }
  ],
  "errors": [ { "path": "/data/locked", "message": "EACCES: permission denied" } ]
}
```

### GET /api/files/download?path=/data/app.log

下载单个文件（支持 `Range` 分段）。响应体为文件流，`Content-Disposition: attachment; filename*=UTF-8''...`。

### POST /api/files/download

多选打包下载（zip 流）。仅选中一个文件时返回单个文件。

请求：

```json
{ "paths": ["/data/archive", "/srv/logs/app.log"], "recursive": true, "showHidden": false }
```

响应 `200`：`Content-Type: application/zip`，`Content-Disposition: attachment; filename="files-20240501-100000.zip"`。

### POST /api/files/delete　（也支持 DELETE /api/files，请求体相同）

**高危操作**：必须携带正确的 TOTP 二次验证码。

请求：

```json
{ "paths": ["/data/app.log", "/data/archive"], "totp": "123456", "recursive": false }
```

响应 `200`（部分失败不影响整体返回）：

```json
{
  "count": 1,
  "deleted": [ { "path": "/data/app.log", "type": "file", "size": 1024 } ],
  "failed": [ { "path": "/data/archive", "code": "DIRECTORY_NOT_EMPTY", "message": "目录非空，需 recursive=true" } ]
}
```

约束：一次最多 `MAX_DELETE_PATHS` 个路径；禁止删除授权根目录自身；TOTP 验证码 30 秒有效、同一验证码不可重放（响应 `403 TOTP_INVALID`）。

---

## 3. TOTP 二次验证

流程：`POST /api/totp/setup` 生成密钥与二维码（**只能生成一次**）→ 用验证器扫码 → `POST /api/totp/verify` 激活。激活后删除接口才可用。

### GET /api/totp/status

```json
{
  "configured": true,
  "enabled": true,
  "issuer": "file-manage",
  "account": "admin",
  "digits": 6,
  "period": 30,
  "algorithm": "SHA1",
  "paramsChanged": false,
  "window": 1,
  "preventReplay": true,
  "createdAt": "2024-05-01T10:00:00.000Z",
  "enabledAt": "2024-05-01T10:01:00.000Z",
  "usedCount": 3
}
```

- `digits` / `period` / `algorithm` 是**实际参与校验**的参数：已绑定时为 `setup` 时的参数快照，
  未绑定时为环境变量（`TOTP_DIGITS` / `TOTP_PERIOD` / `TOTP_ALGORITHM`）的值。
- `paramsChanged` 为 `true` 表示环境变量参数与已绑定参数不一致：已绑定的验证器**仍按绑定时的参数工作**，
  想让新参数生效必须命令行 `reset` 后重新绑定。
- 未生成时 `configured`/`enabled` 为 `false`，其余字段表示将来会使用的参数。

### POST /api/totp/setup

生成 TOTP 密钥（持久化到 `DATA_DIR/totp.json`）。若已生成过 → `409 TOTP_ALREADY_CONFIGURED`（**不提供重置 API**，重置只能用命令行，见 README）。

响应 `200`：

```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "otpauthUrl": "otpauth://totp/file-manage:admin?secret=...&issuer=file-manage&algorithm=SHA1&digits=6&period=30",
  "qrCodeDataUrl": "data:image/png;base64,...",
  "digits": 6,
  "period": 30,
  "algorithm": "SHA1"
}
```

### GET /api/totp/qrcode

返回当前密钥的二维码 PNG（`Content-Type: image/png`）。支持 `?token=`，可直接用作 `<img src>`。已生成但未激活时同样可用；未生成 → `409 TOTP_NOT_CONFIGURED`。

### POST /api/totp/verify

激活 TOTP。

请求：`{ "code": "123456" }`

响应 `200`：`{ "enabled": true, "enabledAt": "2024-05-01T10:01:00.000Z" }`

### 命令行重置（非 API）

```bash
node dist/cli/totp.js status   # 查看状态
node dist/cli/totp.js reset    # 清除密钥（重置后需重新 setup）
```

---

## 4. 系统

### GET /healthz

无需认证。`200 { "status": "ok" }`

### GET /api/system/info

```json
{
  "name": "file-manage",
  "version": "1.0.0",
  "node": "v22.21.0",
  "uptimeSeconds": 12,
  "serverTime": "2024-05-01T10:00:00.000Z",
  "allowedRoots": ["/data"],
  "limits": { "maxListFiles": 5000, "maxListDepth": 16, "maxDeletePaths": 1000, "maxZipFiles": 20000 },
  "totp": { "configured": true, "enabled": true }
}
```

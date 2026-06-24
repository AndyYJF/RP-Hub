# Roleplay Hub · 多用户 + 后台管理 部署说明

在原 Roleplay Hub 纯前端基础上，新增了完整的多用户体系与后台管理功能，并保持「本地模式」可用——未登录时与原项目完全一致。

## 功能概览

- **多用户隔离**：每个用户拥有独立的角色卡、对话、记忆、设置、预设等数据，互不干扰。
- **公共角色库**：用户可提交角色卡到公共库；管理员审核后所有人可浏览/下载。
- **JWT 认证**：用户名 + 密码 + 刷新令牌轮转，access token 15 分钟，refresh token 30 天。
- **后台管理** (`admin.html`)：
  - 系统统计（用户/角色卡/登录趋势，支持 24h / 7d / 30d / 全部）
  - 用户管理（增删改查、封禁/解封、改密、配额、API Key 绑定、升降管理员）
  - 角色卡审核（预览、通过、拒绝带理由、下架）
  - 公告管理（创建/编辑/置顶/失效）
  - API 用量统计（对接 new-api 子 key 后可统计每用户 token 用量）
  - 审计日志（登录、注册、所有管理员操作）
- **本地模式兼容**：未登录用户仍可纯前端使用，所有原功能不变。
- **Docker Compose 一键部署**。

## 目录结构

```text
RP-Hub/
├── index.html            # 主应用（已集成服务端模式开关）
├── account.html          # 登录/注册/账号管理页
├── admin.html            # 后台管理面板
├── assets/
│   ├── css/styles.css
│   └── js/
│       ├── app.js        # 主应用逻辑（新增同步钩子，本地模式不受影响）
│       ├── server-sync.js# 【新增】服务端同步层（fetch + JWT 自动刷新）
│       ├── card-utils.js
│       ├── ui-select.js
│       └── utils.js
├── character/            # 角色卡编辑器子页
├── server/               # 【新增】Node.js + Express 后端
│   ├── src/
│   │   ├── index.js          # 入口
│   │   ├── config.js         # 环境配置
│   │   ├── db.js             # SQLite + 迁移
│   │   ├── middleware/       # auth / error
│   │   ├── routes/           # auth / sync / library / admin / announcements
│   │   ├── utils/jwt.js
│   │   └── scripts/init-admin.js
│   ├── package.json
│   ├── .env.example
│   └── data/                 # SQLite 数据库（运行时生成）
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## 快速部署（Docker Compose，推荐）

```bash
# 1. 复制环境变量并修改密钥
cp .env.example .env
#   务必修改 JWT_SECRET / JWT_REFRESH_SECRET / ADMIN_PASSWORD

# 2. 构建并启动
docker compose up -d --build

# 3. 访问
#    应用首页：http://localhost:3000/
#    账号页：  http://localhost:3000/account.html
#    后台：    http://localhost:3000/admin.html
```

首次启动时会自动创建管理员账号（用户名/密码来自 `.env`）。**请登录后立即在账号页修改密码。**

数据持久化在 Docker volume `rphub-data`，备份只需备份该 volume。

## 本地开发部署（无 Docker）

```bash
cd server
cp .env.example .env
npm install            # Node 24+ 使用内置 node:sqlite，无需编译
npm run init-admin     # 创建管理员
npm start              # 默认 3000 端口
```

前端开发时可直接双击 `index.html`，然后在「账号」页填入 `http://localhost:3000` 作为服务器地址；或用 VS Code Live Server 启动前端。

## API 一览

| 模块 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| 认证 | `POST /api/auth/register` | - | 注册（受 `ALLOW_REGISTER` 开关） |
|      | `POST /api/auth/login` | - | 登录 |
|      | `POST /api/auth/refresh` | - | 刷新 access token |
|      | `POST /api/auth/logout` | - | 注销 |
|      | `GET  /api/auth/me` | user | 当前用户信息 |
|      | `PATCH /api/auth/me` | user | 改昵称/头像/API Key/密码 |
| 同步 | `GET  /api/sync/all` | user | 拉取全部数据 |
|      | `PUT  /api/sync/global/:name` | user | 写全局字段 |
|      | `GET  /api/sync/global/:name` | user | 读全局字段 |
|      | `PUT  /api/sync/scoped/:name/:id` | user | 写 scoped 字段（chat/memories） |
|      | `POST /api/sync/bulk` | user | 批量写 |
|      | `DELETE /api/sync/wipe` | user | 清空自己的所有数据 |
| 角色库 | `GET  /api/library` | - | 公共角色卡列表（分页/搜索/标签） |
|       | `GET  /api/library/tags` | - | 标签聚合 |
|       | `GET  /api/library/:uuid` | optional | 下载角色卡 |
|       | `POST /api/library/submit` | user | 提交角色卡到公共库 |
|       | `GET  /api/library/my/submissions` | user | 我的提交 |
|       | `DELETE /api/library/my/:uuid` | user | 撤下自己的角色卡 |
| 公告 | `GET /api/announcements` | - | 当前生效的公告 |
| 管理 | `GET/PATCH/DELETE /api/admin/users[/:id]` | admin | 用户增删改查 |
|     | `POST /api/admin/users` | admin | 新建用户 |
|     | `GET /api/admin/stats` | admin | 系统统计 |
|     | `GET /api/admin/audit` | admin | 审计日志 |
|     | `GET/POST/PATCH/DELETE /api/admin/announcements[/:id]` | admin | 公告 CRUD |
|     | `GET /api/admin/list` | admin | 全部角色卡（含待审/拒绝/下架） |
|     | `GET /api/admin/pending` | admin | 待审核列表 |
|     | `POST /api/admin/review/:id` | admin | 审核角色卡 |
|     | `GET /api/admin/card/:id` | admin | 预览角色卡完整数据 |
|     | `GET /api/admin/api-usage[/summary]` | admin | API 用量统计 |

## 对接 new-api 自建站点

1. 在后台「用户管理」中给每个用户绑定一个 `apiKey`（通常是 new-api 创建的子 key）。
2. 用户在「账号」页可看到自己绑定的 key（脱敏显示），应用层调用大模型 API 时使用此 key。
3. 若需服务端代理转发并统计 token，可自行扩展 `server/src/routes/` 添加 `/api/proxy/chat` 转发到 new-api，并在 `api_usage` 表写入用量。本仓库已预留 `api_usage` 表与统计接口。

## 安全提示

- **务必修改** `.env` 中的 `JWT_SECRET` / `JWT_REFRESH_SECRET`（建议至少 32 字符随机串）。
- **务必修改** 默认管理员密码 `ADMIN_PASSWORD`，并在登录后通过账号页改密。
- 生产环境建议把 `CORS_ORIGIN` 设为你的实际前端域名（而非 `*`）。
- SQLite 数据库文件 `server/data/rphub.db` 包含用户密码哈希与所有数据，请定期备份并限制文件权限。
- 项目遵循 CC BY-NC 4.0 协议，**禁止商业使用**。

## 从纯前端模式升级到多用户模式

如果你之前在用纯前端版本，已有本地数据：
1. 启动后端后，进入 `account.html` 注册/登录。
2. 打开「服务端模式」开关。
3. 回到 `index.html`，本地数据会自动合并并推送到服务端。
4. 之后在其它设备登录同一账号即可拉取数据。

## 与原项目的关系

- 前端 `app.js` 仅在 `saveData` / `onMounted` 处新增了**非阻塞**的同步钩子；未登录或关闭服务端模式时，这些钩子立即 return，行为与原项目完全一致。
- 所有新增前端逻辑都在 `server-sync.js`、`account.html`、`admin.html` 中，未改动原 UI。

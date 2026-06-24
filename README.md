# Roleplay Hub · 多用户版

[![License: CC BY-NC 4.0](https://img.shields.io/badge/License-CC%20BY--NC%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc/4.0/)
[![Vue](https://img.shields.io/badge/Vue-3-4FC08D.svg?logo=vue.js)](https://vuejs.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![DaisyUI](https://img.shields.io/badge/DaisyUI-5A0EF8?logo=daisyui&logoColor=white)](https://daisyui.com/)
[![Node](https://img.shields.io/badge/Node-24-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![SQLite](https://img.shields.io/badge/SQLite-内置-003B57?logo=sqlite&logoColor=white)](https://nodejs.org/)

> **基于 [STA1N156/RP-Hub](https://github.com/STA1N156/RP-Hub) 的二次开发版本，新增多用户体系、云端数据同步、公共角色库与后台管理。**

---

## 致谢与声明

本项目是 **[STA1N156/RP-Hub](https://github.com/STA1N156/RP-Hub)** 的二次开发版本（二改）。

- **原项目**：[https://github.com/STA1N156/RP-Hub](https://github.com/STA1N156/RP-Hub) by [@STA1N156](https://github.com/STA1N156)
- **原项目许可**：[CC BY-NC 4.0](./LICENSE)（知识共享-署名-非商业性使用 4.0）
- **本项目**：在原项目基础上新增后端与多用户功能，同样遵循 CC BY-NC 4.0 协议

> **感谢原作者 STA1N156 开源了优秀的 RP-Hub 项目，本二改版本在其基础上扩展了多用户能力。**

**【免责与授权声明】**  
本项目基于 **[CC BY-NC 4.0](./LICENSE)** 开源。**明确禁止任何形式的商业化使用（包括但不限于：作为收费服务提供、打包在付费产品中售卖、在产品内植入广告盈利等）。**

---

## 二改新增内容

在原纯前端项目基础上，新增了以下功能（详见 [DEPLOY.md](./DEPLOY.md)）：

### 多用户体系
- JWT 认证（用户名 + 密码 + 刷新令牌轮转）
- 用户数据云端同步（基于时间戳的智能合并，非整体覆盖）
- 本地模式 / 服务端模式可切换（未登录时与原项目完全一致）

### 公共角色库（自建）
- 用户提交角色卡 → 管理员审核 → 公共展示 → 其他用户下载
- 与原作者的「万相广场」并存，侧边栏明确区分

### 后台管理（`admin.html`）
- 系统统计（用户/角色卡/登录趋势）
- 用户管理（增删改查、封禁/解封、API Key 绑定、配额）
- 角色卡审核（预览、通过、拒绝带理由、下架）
- 公告管理（创建/编辑/置顶，前端主页自动展示）
- API 用量统计、审计日志

### 站点公告系统
- 管理员发布公告 → 前端主页弹窗展示（区别于原版本更新日志）

### 部署
- Docker Compose 一键部署
- Caddy 反向代理 + 自动 HTTPS
- systemd 服务管理

---

## 目录结构

```text
RP-Hub/
├── index.html            # 主应用（已集成服务端模式，本地模式不受影响）
├── account.html          # 【新增】登录/注册/账号管理页
├── admin.html            # 【新增】后台管理面板
├── character/            # 原项目辅助页面
├── assets/
│   ├── css/styles.css    # 原项目样式
│   └── js/
│       ├── app.js        # 原项目核心逻辑（新增同步钩子，本地模式不受影响）
│       ├── server-sync.js# 【新增】服务端同步层
│       ├── card-utils.js # 原项目角色卡工具
│       ├── ui-select.js  # 原项目选择器组件
│       └── utils.js      # 原项目工具函数
├── server/               # 【新增】Node.js + Express 后端
│   └── src/
│       ├── index.js      # 入口
│       ├── config.js     # 环境配置
│       ├── db.js         # SQLite + 迁移（使用 Node 24 内置 node:sqlite）
│       ├── middleware/   # auth / error
│       ├── routes/       # auth / sync / library / admin / announcements
│       └── utils/jwt.js
├── Dockerfile            # 【新增】
├── docker-compose.yml    # 【新增】
├── DEPLOY.md             # 【新增】部署文档
├── LICENSE               # 原项目 LICENSE（CC BY-NC 4.0，保持不变）
└── README.md             # 本文件
```

---

## 快速开始

### 纯前端模式（与原项目一致）

双击打开 `index.html` 即可，无需后端。所有原项目功能完全不受影响。

### 多用户模式（完整部署）

详见 [DEPLOY.md](./DEPLOY.md)。简要步骤：

```bash
# Docker Compose
cp .env.example .env   # 修改 JWT 密钥和管理员密码
docker compose up -d --build

# 或手动部署
cd server
cp .env.example .env
npm install
npm run init-admin
npm start
```

---

## 协议与许可

**[Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)](https://creativecommons.org/licenses/by-nc/4.0/deed.zh-hans)**

- **署名**：本项目标注了原作者 [STA1N156](https://github.com/STA1N156) 及原项目链接
- **非商业性使用**：禁止任何形式的商业化使用
- **二改声明**：原 README 注明"二改需经作者授权"，使用前请确认已获原作者许可

详细许可条款请参见 [`LICENSE`](./LICENSE) 文件（与原项目一致，未修改）。

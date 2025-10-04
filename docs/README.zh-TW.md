
# Unla - MCP Gateway

> 🚀 立即將現有的 MCP Servers 和 APIs 轉換為 [MCP](https://modelcontextprotocol.io/) 端點 — 無需更改任何一行程式碼。

[![English](https://img.shields.io/badge/English-Click-yellow)](../README.md)
[![简体中文](https://img.shields.io/badge/简体中文-点击查看-orange)](README.zh-CN.md)
[![繁體中文](https://img.shields.io/badge/繁體中文-點擊查看-blue)](README.zh-TW.md)
[![Release](https://img.shields.io/github/v/release/mcp-ecosystem/mcp-gateway)](https://github.com/amoylab/unla/releases)
[![文件](https://img.shields.io/badge/文件-線上閱讀-blue)](https://docs.unla.amoylab.com)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/mcp-ecosystem/mcp-gateway)
[![Discord](https://img.shields.io/badge/Discord-加入討論-5865F2?logo=discord&logoColor=white)](https://discord.gg/udf69cT9TY)
[![Go Report Card](https://goreportcard.com/badge/github.com/amoylab/unla)](https://goreportcard.com/report/github.com/amoylab/unla)
[![Snyk Security](https://img.shields.io/badge/Snyk-Secure-blueviolet?logo=snyk)](https://snyk.io/test/github/mcp-ecosystem/mcp-gateway)

---

> ⚡ **注意**：Unla 正處於快速開發階段！我們致力於維持向後相容性，但無法百分之百保證。升級時請務必仔細檢查版本變更。由於快速迭代，文件更新有時可能會稍微延遲。如果您遇到任何問題，歡迎透過 [Discord](https://discord.gg/udf69cT9TY) 或 [Issues](https://github.com/amoylab/unla/issues) 搜尋或尋求協助 ❤️

---

## ✨ 什麼是 Unla？

**Unla** 是一個用 Go 編寫的輕量級高可用閘道服務。它讓個人和組織能夠透過設定方式將現有的 MCP Servers 和 APIs 轉換為符合 [MCP 協定](https://modelcontextprotocol.io/) 的服務，**完全無需更改程式碼**。

https://github.com/user-attachments/assets/69480eda-7aa7-4be7-9bc7-cae57fe16c54

### 🔧 核心設計理念

- ✅ 零侵入：平台中立，支援部署在裸機、虛擬機、ECS、Kubernetes 等環境，無需修改現有基礎設施
- 🔄 設定驅動：透過 YAML 設定即可將既有 API 轉換為 MCP Server，無需修改程式碼
- 🪶 輕量高效：極致輕量化架構設計，不在效能與高可用性上妥協
- 🧭 內建管理介面：開箱即用的 Web UI，降低學習與維運成本

---

## 🚀 快速開始

Unla 支援開箱即用的 Docker 部署方式。完整的部署與設定說明請參考[文件](https://docs.unla.amoylab.com/getting-started/quick-start)。

### 使用 Docker 快速啟動

設定環境變數：

```bash
export APISERVER_JWT_SECRET_KEY="changeme-please-generate-a-random-secret"
export SUPER_ADMIN_USERNAME="admin"
export SUPER_ADMIN_PASSWORD="changeme-please-use-a-secure-password"
```

啟動容器：

```bash
docker run -d \
  --name unla \
  -p 8080:80 \
  -p 5234:5234 \
  -p 5235:5235 \
  -p 5335:5335 \
  -p 5236:5236 \
  -e ENV=production \
  -e TZ=Asia/Shanghai \
  -e APISERVER_JWT_SECRET_KEY=${APISERVER_JWT_SECRET_KEY} \
  -e SUPER_ADMIN_USERNAME=${SUPER_ADMIN_USERNAME} \
  -e SUPER_ADMIN_PASSWORD=${SUPER_ADMIN_PASSWORD} \
  --restart unless-stopped \
  ghcr.io/amoylab/unla/allinone:latest
```

### 存取與設定

1. 存取 Web 介面：
   - 在瀏覽器中開啟 http://localhost:8080/
   - 使用您設定的管理員帳號密碼登入

2. 新增 MCP Server：
   - 複製設定檔：https://github.com/amoylab/unla/blob/main/configs/proxy-mock-server.yaml
   - 在 Web 介面上點擊「Add MCP Server」
   - 貼上設定並儲存

### 可用端點

設定完成後，服務將在以下端點可用：

- MCP SSE: http://localhost:5235/mcp/user/sse
- MCP SSE Message: http://localhost:5235/mcp/user/message
- MCP Streamable HTTP: http://localhost:5235/mcp/user/mcp

在 MCP Client 中設定 `/sse` 或 `/mcp` 後綴的 URL 即可開始使用。

### 測試

您可以透過以下兩種方式測試服務：

1. 使用 Web 介面中的 MCP Chat 頁面
2. 使用您自己的 MCP Client（**推薦**）

📖 查看完整指南 → [快速開始文件 »](https://docs.unla.amoylab.com/getting-started/quick-start)

---

## 🚀 核心特性

### 🔌 協定與代理能力
- [x] 支援將 RESTful API 轉換為 MCP Server — Client → MCP Gateway → APIs
- [x] 支援代理 MCP 服務 — Client → MCP Gateway → MCP Servers
- [ ] 支援將 gRPC 轉換為 MCP Server — Client → MCP Gateway → gRPC
- [ ] 支援將 WebSocket 轉換為 MCP Server — Client → MCP Gateway → WebSocket
- [x] 支援 MCP SSE
- [x] 支援 MCP Streamable HTTP
- [x] 支援 MCP 回應包含文字、圖片和音訊

### 🧠 會話與多租戶支援
- [x] 持久化與可恢復的會話支援
- [x] 多租戶支援
- [ ] 支援 MCP 分組聚合

### 🛠 設定與管理
- [x] 自動設定拉取與無縫熱重載
- [x] 設定持久化支援（Disk/SQLite/PostgreSQL/MySQL）
- [x] 支援設定更新同步機制（OS Signal/HTTP/Redis PubSub）
- [x] 設定版本控制

### 🔐 安全性與認證
- [x] MCP Server 前置 OAuth 認證

### 🖥 使用者介面
- [x] 直觀輕量的管理介面

### 📦 部署與維運
- [x] 服務多副本支援
- [x] Docker 支援
- [x] Kubernetes 與 Helm 部署支援

---

## 📚 文件

更多使用方式、設定範例、整合說明請造訪文件網站：

👉 **https://docs.unla.amoylab.com**

---

## 📄 授權條款

本專案採用 [MIT 授權條款](../LICENSE)。

## 💬 加入微信社群

掃描下方 QR Code 加入微信，請備註：`mcp-gateway`、`mcpgw` 或 `unla`

<img src="../web/public/wechat-qrcode.png" alt="微信 QR Code" width="350" height="350" />

## 📈 Star 歷程

[![Star History Chart](https://api.star-history.com/svg?repos=AmoyLab/Unla&type=Date)](https://star-history.com/#AmoyLab/Unla&Date)

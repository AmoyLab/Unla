# Unla - MCP Gateway

> 🚀 将现有 MCP Servers 和 APIs 快速转化为 [MCP](https://modelcontextprotocol.io/) 服务，无需改动任何一行代码。

[![English](https://img.shields.io/badge/English-Click-yellow)](../README.md)
[![简体中文](https://img.shields.io/badge/简体中文-点击查看-orange)](README.zh-CN.md)
[![Release](https://img.shields.io/github/v/release/mcp-ecosystem/mcp-gateway)](https://github.com/amoylab/unla/releases)
[![文档](https://img.shields.io/badge/文档-在线阅读-blue)](https://docs.unla.amoylab.com)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/mcp-ecosystem/mcp-gateway)
[![Discord](https://img.shields.io/badge/Discord-加入讨论-5865F2?logo=discord&logoColor=white)](https://discord.gg/udf69cT9TY)
[![Go Report Card](https://goreportcard.com/badge/github.com/amoylab/unla)](https://goreportcard.com/report/github.com/amoylab/unla)
[![Snyk Security](https://img.shields.io/badge/Snyk-Secure-blueviolet?logo=snyk)](https://snyk.io/test/github/mcp-ecosystem/mcp-gateway)

---

> ⚡ **注意**：Unla 正在快速迭代中！我们会尽力保证向下兼容，但无法百分百承诺兼容性。升级版本时一定要留意版本变更情况️。同时由于更新频繁，文档内容可能存在一定延迟，如遇问题欢迎通过 [Discord](https://discord.gg/udf69cT9TY) 或 [Issue](https://github.com/amoylab/unla/issues) 搜索和求助❤️

---

## ✨ Unla 是什么？

**Unla** 是一个用 Go 编写的轻量高可用网关服务，帮助个人与企业将已有的 MCP Servers 和 APIs 通过配置方式转换为符合 [MCP 协议](https://modelcontextprotocol.io/) 的服务，无需改动任何代码。

https://github.com/user-attachments/assets/69480eda-7aa7-4be7-9bc7-cae57fe16c54

### 🔧 核心设计理念

- ✅ 零侵入：平台中立，适配物理机、虚拟机、ECS、K8s 等环境，无需改动现有基础设施
- 🔄 配置驱动：通过 YAML 配置即可将存量 API 转换为 MCP Server，无需改代码
- 🪶 轻量高效：架构极致轻量，拒绝在性能与高可用性上妥协
- 🧭 内置管理界面：开箱即用的 Web UI，降低学习与运维成本

---

## 🚀 快速开始

Unla 提供开箱即用的 Docker 启动方式。完整部署与配置说明请参考 [文档](https://docs.unla.amoylab.com/getting-started/quick-start)。

### 一键启动 Unla

配置环境变量：

```bash
export APISERVER_JWT_SECRET_KEY="changeme-please-generate-a-random-secret"
export SUPER_ADMIN_USERNAME="admin"
export SUPER_ADMIN_PASSWORD="changeme-please-use-a-secure-password"
```

一键拉起：

```bash
docker run -d \
  --name mcp-gateway \
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

> 在中国境内的设备可以使用阿里云仓库的镜像并自定义模型（这边示例是千问）：
>
> ```bash
> export APISERVER_JWT_SECRET_KEY="changeme-please-generate-a-random-secret"
> export SUPER_ADMIN_USERNAME="admin"
> export SUPER_ADMIN_PASSWORD="changeme-please-use-a-secure-password"
> ```
>
> ```bash
> docker run -d \
>   --name unla \
>   -p 8080:80 \
>   -p 5234:5234 \
>   -p 5235:5235 \
>   -p 5335:5335 \
>   -p 5236:5236 \
>   -e ENV=production \
>   -e TZ=Asia/Shanghai \
>   -e APISERVER_JWT_SECRET_KEY=${APISERVER_JWT_SECRET_KEY} \
>   -e SUPER_ADMIN_USERNAME=${SUPER_ADMIN_USERNAME} \
>   -e SUPER_ADMIN_PASSWORD=${SUPER_ADMIN_PASSWORD} \
>   --restart unless-stopped \
>   registry.ap-southeast-1.aliyuncs.com/amoylab/unla-allinone:latest
> ```

### 访问和配置

1. 访问 Web 界面：
   - 在浏览器中打开 http://localhost:8080/
   - 使用配置的管理员账号密码登录

2. 添加 MCP Server：
   - 复制配置文件：https://github.com/amoylab/unla/blob/main/configs/proxy-mock-server.yaml
   - 在 Web 界面上点击 "Add MCP Server"
   - 粘贴配置并保存

### 可用端点

配置完成后，服务将在以下端点可用：

- MCP SSE: http://localhost:5235/mcp/user/sse
- MCP SSE Message: http://localhost:5235/mcp/user/message
- MCP Streamable HTTP: http://localhost:5235/mcp/user/mcp

在MCP Client中配置`/sse`或`/mcp`后缀的url即可开始使用

### 测试

您可以通过以下两种方式测试服务：

1. 使用 Web 界面中的 MCP Chat 页面
2. 使用您自己的 MCP Client（**推荐**）

📖 查看完整指南 → [快速开始文档 »](https://docs.unla.amoylab.com/getting-started/quick-start)

---

## 🚀 核心特性

### 🔌 协议与代理能力
- [x] 支持RESTful API 到 MCP Server 的转换，Client->MCP Gateway->APIs
- [x] 支持代理MCP服务，Client->MCP Gateway->MCP Servers
- [ ] gRPC 到 MCP Server 的转换，Client->MCP Gateway->gRPC
- [ ] WebSocket 到 MCP Server 的转换，Client->MCP Gateway->WebSocket
- [x] MCP SSE支持
- [x] MCP Streamable HTTP支持
- [x] 支持MCP文本、图像、音频结果返回

### 🧠 会话与多租户
- [x] 会话持久化与恢复支持
- [x] 支持多租户
- [ ] 支持MCP分组聚合

### 🛠 配置与管理
- [x] 自动配置拉取与无缝热重载
- [x] 配置持久化支持(Disk/SQLite/PostgreSQL/MySQL)
- [x] 支持配置更新同步机制(OS Signal/HTTP/Redis PubSub)
- [x] 配置版本控制

### 🔐 安全与认证
- [x] MCP Server前置OAuth认证

### 🖥 用户界面
- [x] 直观轻量的管理界面

### 📦 部署与运维
- [x] 服务多副本支持
- [x] Docker 支持
- [x] Kubernetes与Helm部署支持

---

## 📚 文档

更多使用方式、配置示例、集成说明请访问文档站点：

👉 **https://docs.unla.amoylab.com**

---

## 📄 许可证

本项目采用 [MIT 协议](../LICENSE)。

## 💬 加入社区微信群

扫描下方二维码添加微信，备注：`mcp-gateway`, `mcpgw`或`unla`

<img src="../web/public/wechat-qrcode.png" alt="微信群二维码" width="350" height="350" />

## 📈 Star 历史

[![Star History Chart](https://api.star-history.com/svg?repos=AmoyLab/Unla&type=Date)](https://star-history.com/#AmoyLab/Unla&Date)


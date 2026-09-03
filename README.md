# Packet Lens

[![Release](https://img.shields.io/github/v/release/9600bits/packet-lens?display_name=tag&sort=semver)](https://github.com/9600bits/packet-lens/releases/latest)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%2F%2011-2563eb)](https://github.com/9600bits/packet-lens/releases/latest)
[![License](https://img.shields.io/github/license/9600bits/packet-lens)](./LICENSE)

Packet Lens 是一套面向个人运维场景的本地网络与基础设施工具。它把抓包分析、网络探测、机柜与服务器台账、安全审计、IP/VLAN 规划、故障诊断和本地知识检索放在同一个工作台中。

应用默认使用浅色专业运维界面，以 Windows 单文件 EXE 运行。除主动启用的 AI 请求和用户发起的网络操作外，业务数据保存在本机。

> 当前版本：`v0.7.0`。本项目不包含 Kubernetes 功能，也没有保留 K8s 隐藏入口或依赖。

## 快速开始

1. 从 [GitHub Releases](https://github.com/9600bits/packet-lens/releases/latest) 下载 `PacketLens.exe`。
2. 双击运行，程序会自动打开本机浏览器。
3. 默认访问地址为 `http://127.0.0.1:8321`。

目标机器不需要安装 Python、Wireshark 或 Npcap。程序只允许监听 `127.0.0.1`、`::1` 或 `localhost`，不支持直接对外提供 Web 服务。

常用启动参数：

```powershell
.\PacketLens.exe --port 9000
.\PacketLens.exe --host 127.0.0.1 --port 9000 --no-browser
```

## 功能概览

| 工作域 | 主要能力 |
| --- | --- |
| 网络分析 | 离线解析 pcap/pcapng/cap、规则命中、流量过滤、报文详情、Ping/HTTP/TCP 探测与定时监控 |
| 资产与连接 | 机房和机柜台账、U 位占用、容量统计、服务器登记、SSH/RDP 连接、凭据管理 |
| 安全中心 | 暴露面发现、网络设备配置审计、异常事件汇总、离线安全报告 |
| 规划与诊断 | `/8` 至 `/30` 的 IP/VLAN 与 VLSM 规划、DNS/Ping/路由/TCP/TLS/HTTP 一键诊断 |
| 知识与 AI | 本地文档导入、中文全文检索、来源引用、OpenAI 兼容服务和 Ollama |

### 抓包分析

- 支持 `.pcap`、`.pcapng` 和 `.cap`，单次默认最多解析 50,000 个报文。
- 展示五元组、协议、时间戳、TCP Flags、规则结论和载荷十六进制预览。
- 支持按协议、规则、关键词和“仅显示命中”过滤。
- 内置 TCP RST、重传、零窗口、SYN 半开、端口扫描、DNS 失败、HTTP 4xx/5xx、TLS Alert 和 ICMP 异常规则。
- 可针对整体、选中报文或单条流生成本地 Markdown 报告。

### 网络探测与安全

- 批量执行 Ping、HTTP 状态检查和 TCP 端口探测。
- 创建定时监控任务，查看运行历史和结果差异。
- 发现主机、开放端口和服务暴露面，仅用于已获授权的目标。
- 导入常见网络设备文本配置，检查管理协议、访问控制和高风险配置。
- 巡检、诊断与安全异常统一进入事件中心。

### 机柜与服务器

- 管理机房、多个机柜、设备、预留 U 位、模板、容量和机柜对比。
- 多机柜支持一行或两行展开、分行横向滚动与自定义分配。
- 服务器台账与机柜台账相互独立，支持环境、标签和备注。
- SSH 支持密码、私钥、私钥口令、主机指纹确认和单级跳板机。
- RDP 调用 Windows `mstsc.exe`，可选择是否向 Windows Credential Manager 写入登录凭据。
- 固定白名单巡检基础信息、存储、网络、systemd 服务、安全状态和容器状态。
- 支持手动巡检、定时巡检、脱敏快照和前后差异。

### IP/VLAN 规划与诊断

- 支持 IPv4 `/8` 至 `/30`，可按主机数量自动选取掩码或手动指定。
- 本地 VLSM 规划器检查 CIDR、子网边界、容量、VLAN ID 重复和网段重叠。
- AI 可以生成结构化规划草案，但最终结果必须通过本地规划器校验后才能保存。
- 已保存规划可以再次载入、修改、计算和请求 AI 审核。
- 一键诊断按目标自动组合 DNS、Ping、路由、TCP、TLS、HTTP 和可选 SSH 检查；独立步骤失败不会阻止后续步骤。

### 本地知识与 AI

- 可导入 `.md`、`.txt`、`.log`、`.yaml`、`.yml`、`.json` 和 `.pdf`，单文件上限 20 MB。
- 文件按 SHA-256 去重并分块，通过 jieba 和 SQLite FTS5 完成中文全文检索。
- PDF 仅提取已有文本，扫描版 PDF 暂不支持 OCR。
- 支持 OpenAI 兼容接口和本机 Ollama；没有配置 AI 时，本地分析、规划、诊断和检索仍可使用。
- 云端请求发送前展示来源和实际上下文，默认遮蔽内网 IP；用户确认后才会发送。
- 凭据、Token、私钥等秘密字段始终经过强制脱敏。

AI 配置统一从界面右上角的设置按钮进入，不再提供重复的独立配置菜单。

## 本地数据与安全

运行数据位于 `%APPDATA%\PacketLens`：

| 路径 | 内容 |
| --- | --- |
| `ops.db` | 服务器、连接、凭据元数据、巡检、诊断、事件、网络规划、知识索引和 AI 会话 |
| `cabinets.db` | 机房、机柜、设备、预留位置和模板 |
| `monitor.db` | 网络监控任务与运行记录 |
| `knowledge\` | 用户导入的知识文档 |
| `known_hosts` | 已确认的 SSH 主机指纹 |
| `logs\` | 脱敏后的应用日志目录 |

安全边界：

- 密码、私钥、私钥口令和 AI Key 使用 Windows DPAPI CurrentUser 加密。
- 凭据接口只返回名称、类型、时间和掩码，不返回秘密原文。
- SSH 终端正文只保存在当前连接内存中，不写入数据库。
- 每次启动生成随机访问令牌，并通过 HttpOnly、SameSite=Strict Cookie 建立本机会话。
- 状态变更接口校验 Origin 和 CSRF Token；SSH WebSocket 使用 60 秒短期票据。
- 自动巡检只执行固定只读命令；启用 sudo 时仅尝试 `sudo -n`，不会询问或保存 sudo 密码。
- 从旧版升级时，明文 AI Key 会迁移到 DPAPI 凭据库；遗留 Kubernetes 记录会被一次性清理。

## 支持范围

- 操作系统：Windows 10/11 x64。
- 打包形式：PyInstaller 单文件 EXE。
- SSH 巡检：面向 Ubuntu/Debian、RHEL/CentOS/Rocky/Alma 等 systemd Linux 发行版。
- RDP：依赖 Windows 自带的 `mstsc.exe`。
- AI：OpenAI 兼容聊天/Embedding 接口或本机 Ollama，不内置大模型。
- 网络扫描、安全审计和远程连接仅应在你拥有或明确获准管理的设备与网络中使用。

## 开发

环境要求：Python 3.11+、Node.js 18+、npm。

安装并启动后端：

```powershell
cd backend
python -m pip install -r requirements.txt
python run.py
```

启动前端开发服务器：

```powershell
cd frontend
npm install
npm run dev
```

前端默认运行在 `http://127.0.0.1:5173`，并将 API 请求代理到后端 `8321` 端口。

运行测试：

```powershell
cd backend
python -m pytest tests -q

cd ..\frontend
npm run build
```

## 构建 Windows EXE

在仓库根目录执行：

```powershell
.\build_exe.ps1
```

脚本会先构建 React 前端，再通过 PyInstaller 生成：

```text
dist\PacketLens.exe
```

前端静态资源会嵌入 EXE。未签名的 PyInstaller 程序可能被部分安全软件提示，请从本仓库 Release 下载并核对发行页提供的 SHA-256。

## 版本记录

完整变更参见 [CHANGELOG.md](./CHANGELOG.md)。最新稳定版和 Windows 可执行文件参见 [GitHub Releases](https://github.com/9600bits/packet-lens/releases)。

## 许可证

Packet Lens 使用 [GPL-3.0](./LICENSE) 许可发布。

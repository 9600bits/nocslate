# Packet Lens

一个离线 pcap / pcapng 分析与网络探测工具：纯 Python 解析报文，用规则引擎和本地报告生成器先给出诊断结论；OpenAI 兼容 API 只作为可选的增强解读。运行时不需要安装 Wireshark、Npcap 或 Python。

## 功能

- 支持上传 `.pcap` / `.pcapng` / `.cap` 文件，默认最多解析 50,000 包。
- 按报文列表查看五元组、协议、时间戳、TCP Flags 和 Wireshark 风格中文信息。
- 内置规则：
  - TCP RST / RST+ACK
  - TCP 重传、TCP 零窗口
  - SYN 半开、疑似端口扫描
  - DNS 解析失败
  - HTTP 4xx / 5xx
  - TLS Alert
  - ICMP 目标不可达 / 超时
- 支持协议、规则、关键词和“仅显示命中”过滤。
- 点击报文查看 MAC 地址、TCP 头、规则结论、DNS/HTTP/TLS/ICMP 摘要和载荷十六进制预览。
- 本地离线报告支持整体概览、选中报文和单条流三种范围，输出总体结论、规则命中统计、关键流、重点报文证据、可能原因和排查建议。
- 网络探测中心支持批量 Ping、HTTP 状态检查和 TCP 端口扫描，探测结束后也可以生成对应的本地离线报告。
- AI 分析是可选增强解读，而不是必要分析器；没有网络或没有配置 Key 时，规则引擎、报文浏览和离线报告全部可用。

## 诊断与 AI

抓包分析页和探测页都提供“离线报告”与“AI 增强”两种模式。默认使用离线报告，由本地规则和内置知识库生成 Markdown，不需要网络；可以复制结果或下载 `.md` 文件。

联网后可以打开界面右上角齿轮图标，填写 OpenAI 兼容服务的：

1. `base_url`，例如 `https://api.deepseek.com/v1`
2. `model`
3. `api_key`

配置保存在 exe 同目录的 `config.json`；界面中 API Key 只显示掩码。配置 Base URL 和 API Key 后可以扫描 `/models` 并从返回列表中选择模型。没有配置 Key 时，所有规则分析、报文浏览、探测和离线报告功能都可以正常使用。

> 注意：`config.json` 内的 API Key 是本地明文保存，分发或截图前请先清除。

## 运行打包版

双击 `dist/PacketLens.exe`，程序默认在 `http://127.0.0.1:8321` 启动并自动打开浏览器。

常用参数：

```powershell
.\PacketLens.exe --port 9000
.\PacketLens.exe --host 127.0.0.1 --port 9000 --no-browser
```

上传的 pcap 会复制到系统临时目录 `packet_lens_uploads` 中解析，不会上传到第三方服务器；AI 请求只发送你选择的分析上下文。

## 开发模式

后端：

```powershell
cd backend
python -m pip install -r requirements.txt
python run.py
```

前端：

```powershell
cd frontend
npm install
npm run dev
```

开发前端运行在 `http://127.0.0.1:5173`，API 请求会代理到后端 `8321` 端口。

测试：

```powershell
cd backend
python -m pytest tests -q
```

## 打包 exe

在 Windows 10/11 x64 环境执行：

```powershell
.\build_exe.ps1
```

脚本会先执行 `npm run build`，再调用 PyInstaller 生成 `dist/PacketLens.exe`。前端静态资源已内嵌进 exe；目标机器不需要 Wireshark、Npcap、Python 或管理员权限。

未签名 PyInstaller exe 可能被部分杀毒软件误报，这是常见现象；正式分发时可以做代码签名。

## 许可证

本项目使用 [GPL-3.0](./LICENSE) 授权发布。发行版二进制和源码都可通过 GitHub Releases 获取。

# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 提供该代码仓库的工作指引。

## 项目概述

这是一个 **PPPOE 密码嗅探器** - 一个 Windows 控制台应用程序，用于从网络流量中捕获 PPPOE 认证凭据（用户名/密码）。它通过模拟 PPPOE 接入集中器 (AC) 来拦截 PAP 认证数据包。

## 构建说明

### 前置条件

- 安装了 Visual Studio 的 Windows 系统（使用 PlatformToolset v142）
- WinPcap 4.0.2 或更高版本（已捆绑在 `WpdPack/` 中）

### 构建命令

**使用 Visual Studio：**
```bash
# 在 Visual Studio 中打开 PPPOE.vcxproj 并构建
# 或使用 MSBuild
msbuild PPPOE.vcxproj /p:Configuration=Release /p:Platform=Win32
```

**输出位置：**
- Debug 构建：`Debug/PPPOE.exe`
- Release 构建：`Release/PPPOE.exe`

## 项目结构

```
pppoe_sniffer/
├── pppoe.cpp          # 主入口点和数据包捕获循环
├── common.cpp         # 核心协议实现
├── common.h           # 头文件、结构体和函数声明
├── PPPOE.vcxproj      # Visual Studio 项目文件
└── WpdPack/           # WinPcap 开发工具包
    ├── Include/       # pcap 头文件
    └── Lib/           # wpcap.lib, Packet.lib
```

## 架构

### 核心组件

1. **数据包捕获** (`pppoe.cpp`)
   - 使用 WinPcap 捕获实时流量或读取 pcap 文件
   - 过滤以太网类型 `0x8863`（PPPOE 发现）和 `0x8864`（PPPOE 会话）
   - 支持两种模式：从网卡实时捕获或离线文件分析

2. **协议栈** (`common.cpp`)
   - **发现阶段**：处理 PADI/PADO/PADR/PADS 数据包以建立会话
   - **LCP 阶段**：响应链路控制协议配置请求
   - **PAP 阶段**：从 PAP 认证请求数据包中提取用户名/密码

3. **数据包构造**
   - `build_PPPOE_PACKET()` - 构建发现阶段响应
   - `build_LCP_ACK_PACKET()` - 构建 LCP 确认响应
   - `build_PAP_AUTH_CREQ_PACKET()` - 发送 PAP 认证要求
   - `SendPacket()` - 通过 pcap_sendpacket() 发送构造的数据包

### 关键数据结构

```cpp
// 在 common.h 中定义的协议头
ETHERNET_HEADER   # 以太网 II 头部（14 字节）
PPPOED_HEADER     # PPPOE 头部（6 字节）：版本/类型、代码、会话ID、载荷长度
PPP_HEADER        # PPP 头部（6 字节）：协议、代码、标识符、长度
PPPOE_TAG         # PPPOE 标签结构，用于发现阶段
LCP_OPT           # LCP 配置选项
```

### 执行流程

1. **发现阶段** (`check_PPPOED()`)
   - 收到 PADI → 发送带 AC-Name 标签的 PADO
   - 收到 PADR → 发送会话 ID 为 0x0311 的 PADS
   - 立即发送要求 PAP 认证的 LCP 配置请求

2. **会话阶段** (`check_PPPOES()`)
   - 处理 LCP 配置请求 → 发送 ACK/REJ
   - 当同意 PAP 认证后，发送要求 PAP 的配置请求
   - 从 PAP 认证请求中提取凭据

### MAC 地址行为

程序根据文件名使用两种 MAC 模式：
- **测试 MAC**（默认）：使用硬编码 MAC `01:01:01:02:02:02`
- **真实 MAC**：如果可执行文件名包含 "zpf"，则使用实际网卡 MAC

这由 `UseMacByFileName()` 和 `use_TEST_MAC` 标志控制。

## 使用方法

**实时捕获：**
```bash
PPPOE.exe
# 从列表中选择网卡
# 等待目标发起 PPPOE 连接
```

**离线分析：**
```bash
PPPOE.exe capture.pcap
```

**输出：**
- 凭据打印到控制台
- 保存到可执行文件所在目录的 `PPPoE_帐号密码.txt`

## 重要说明

- 系统需要已安装 WinPcap
- 需要以管理员权限运行才能进行原始数据包捕获/注入
- 对网卡使用混杂模式
- 硬编码会话 ID `0x0311`（PADS_SESSION_ID）
- 硬编码魔术数字 `0x5e630ab8` 用于 LCP
- 代码注释和输出主要为中文

# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 提供该代码仓库的工作指引。

## 项目概述

这是一个 **PPPOE 密码嗅探器** - 一个 Windows 控制台应用程序，用于从网络流量中捕获 PPPOE 认证凭据(用户名/密码)。它通过模拟 PPPOE 接入集中器 (AC) 来拦截 PAP 认证数据包。

## 构建说明

### 前置条件

- 安装了 Visual Studio 的 Windows 系统(使用 PlatformToolset v143)
- Npcap(已捆绑在 `npcap/` 中，需要安装 Npcap 驱动)

### 构建命令

**使用 Visual Studio：**
```bash
# 在 Visual Studio 中打开 PPPOE.vcxproj 并构建
# 或使用 MSBuild
msbuild PPPOE.vcxproj /p:Configuration=Release /p:Platform=Win32
msbuild PPPOE.vcxproj /p:Configuration=Release /p:Platform=x64
```

**输出位置：**
- Win32 Debug 构建：`build/x86/Debug/PPPOE.exe`
- Win32 Release 构建：`build/x86/Release/PPPOE.exe`
- x64 Debug 构建：`build/x64/Debug/PPPOE.exe`
- x64 Release 构建：`build/x64/Release/PPPOE.exe`

## 项目结构

```
pppoe_sniffer/
├── pppoe.cpp          # 主入口点和数据包捕获循环
├── common.cpp         # 核心协议实现
├── common.h           # 头文件、结构体和函数声明
├── PPPOE.vcxproj      # Visual Studio 项目文件
└── npcap/             # Npcap 开发工具包
    ├── Include/       # pcap 头文件
    └── Lib/           # wpcap.lib, Packet.lib (x86/x64/ARM64)
```

## 架构

### 核心组件

1. **数据包捕获** (`pppoe.cpp`)
   - 使用 Npcap 捕获实时流量或读取 pcap 文件
   - 过滤以太网类型 `0x8863`(PPPOE 发现)和 `0x8864`(PPPOE 会话)
   - 支持 BPF 过滤器：包括带 VLAN 标签的 PPPOE 流量
   - 支持两种模式：从网卡实时捕获或离线文件分析

2. **协议栈** (`common.cpp`)
   - **发现阶段**：处理 PADI/PADO/PADR/PADS 数据包以建立会话
   - **LCP 阶段**：响应链路控制协议配置请求
   - **PAP 阶段**：从 PAP 认证请求数据包中提取用户名/密码
   - **VLAN 处理**：自动检测 VLAN 标签并正确解析/构造数据包

3. **数据包构造**
   - `build_PPPOE_PACKET()` - 构建发现阶段响应 (PADO/PADS)
   - `build_LCP_ACK_PACKET()` - 构建 LCP 确认/拒绝响应
   - `build_PAP_AUTH_CREQ_PACKET()` - 发送要求 PAP 认证的 LCP 配置请求
   - `SendPacket()` - 通过 pcap_sendpacket() 发送构造的数据包

### 关键数据结构

```cpp
// 在 common.h 中定义的协议头
ETHERNET_HEADER   # 以太网 II 头部(14 字节)
VLAN_HEADER       # VLAN 标签(4 字节)：TCI + 封装类型
                  #   - vlan_tci: PRI(3 bits) + DEI(1 bit) + VLAN_ID(12 bits)
                  #   - vlan_type: 封装的实际以太网类型(0x8863/0x8864)
PPPOED_HEADER     # PPPOE 头部(6 字节)：版本/类型、代码、会话ID、载荷长度
PPP_HEADER        # PPP 头部(6 字节)：协议、代码、标识符、长度
PPPOE_TAG         # PPPOE 标签结构，用于发现阶段
LCP_OPT           # LCP 配置选项
```

### VLAN 支持实现

**数据包接收流程：**
- `GetActualEtherType()` - 识别外层类型(0x8100=VLAN)，返回内层实际类型
- `GetEthHeaderOffset()` - 计算头部偏移(标准 14 字节或带 VLAN 18 字节)
- 自动侦测：当收到 VLAN 标签包且未手动指定时，自动提取 VLAN ID

**数据包发送流程：**
- 所有构造函数检查 `use_vlan` 标志
- 如启用 VLAN，在以太网头后插入 4 字节 VLAN 标签
- 设置 TCI 字段(VLAN ID + 默认优先级/DEI)

### 执行流程

1. **发现阶段** (`check_PPPOED()`)
   - 收到 PADI → 发送带 AC-Name 标签的 PADO
   - 收到 PADR → 发送会话 ID 为 0x0311 的 PADS
   - 进入 LCP 协商阶段

2. **会话阶段** (`check_PPPOES()`)
   - 处理 LCP 配置请求 → 发送 ACK/REJ
   - 当收到非 PAP 认证请求时，主动发送要求 PAP 的配置请求
   - 从 PAP 认证请求(PAP_AREQ)中提取凭据

### 命令行参数

程序支持以下命令行参数：

- `-v <vlan_id>` / `--vlan <vlan_id>` - 手动指定 VLAN ID (0-4094)
- `-m` / `--mac` - 使用虚拟 MAC 地址 `01:01:01:02:02:02`
- `-f <file>` / `--file <file>` - 分析本地 pcap 文件(离线模式)

## 使用方法

**实时捕获：**
```bash
PPPOE.exe
# 从列表中选择网卡
# 等待目标发起 PPPOE 连接
```

**带 VLAN 的实时捕获：**
```bash
# 自动侦测 VLAN
PPPOE.exe

# 手动指定 VLAN ID
PPPOE.exe -v 100
PPPOE.exe --vlan 100
```

**使用虚拟 MAC 地址：**
```bash
# 使用虚拟MAC（默认使用真实MAC）
PPPOE.exe -m
PPPOE.exe --mac
```

**离线分析：**
```bash
# 使用 -f 参数指定 pcap 文件
PPPOE.exe -f capture.pcap
PPPOE.exe --file capture.pcap

# 带 VLAN 的离线分析
PPPOE.exe -v 100 -f capture.pcap
```

**输出：**
- 凭据打印到控制台
- 保存到可执行文件所在目录的 `PPPoE_帐号密码.txt`

## 重要说明

- 系统需要已安装 Npcap(驱动可从 https://npcap.com/ 下载)
- 需要以管理员权限运行才能进行原始数据包捕获/注入
- 对网卡使用混杂模式
- 硬编码会话 ID `0x0311`(PADS_SESSION_ID)
- 硬编码魔术数字 `0x5e630ab8` 用于 LCP Magic Number
- 代码注释和输出主要为中文
- 支持 x86 (Win32) 和 x64 架构编译

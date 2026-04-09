# PPPOE密码嗅探器

## 项目简介

这是一个用于捕获PPPOE认证凭据（用户名/密码）的Windows控制台应用程序。它通过模拟PPPOE接入集中器(AC)来拦截网络中的PAP认证数据包，可用于找回本机或局域网中保存的宽带账号密码。

---

## 关于本仓库

> **原作者**: zhupf (xzfff@126.com)
> 
> **版权所有**: (C) 2008 zhupf
> 
> **说明**: 我于**2012年6月**接触到这份源码，并非原作者本人。
> 
> **来源**: 原压缩包为 `"源码PPPOE_07月02日08点43分"` 
>
> 现在将其开源发布出来，仅供**学习交流**和**资料存档**之用。版权归原作者所有。

---

## 功能特性

- 从网络流量中嗅探PPPOE拨号的用户名和密码
- 支持捕获本机或局域网内其他设备的宽带连接凭据
- 支持从实时网卡流量捕获或离线pcap文件分析
- 支持xDSL宽带连接、宽带数字电视机顶盒、路由器等设备
- 自动保存捕获结果到本地文件

## 系统要求

- Windows操作系统
- 安装 [WinPcap](https://www.winpcap.org/) 4.1.2 或更高版本（已捆绑 `WpdPack/`）
- 管理员权限（用于原始数据包捕获/注入）
- Visual Studio（用于编译）

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

## 编译方法

### 使用 Visual Studio

1. 在 Visual Studio 中打开 `PPPOE.vcxproj`
2. 选择 Release / Win32 平台
3. 点击生成

### 使用 MSBuild 命令行

```bash
msbuild PPPOE.vcxproj /p:Configuration=Release /p:Platform=Win32
```

**输出位置:**
- Debug 构建：`Debug/PPPOE.exe`
- Release 构建：`Release/PPPOE.exe`

## 使用方法

### 实时捕获模式

直接运行程序，选择网卡后监听网络：

```bash
PPPOE.exe
```

1. 程序会列出可用的网卡，输入序号选择
2. 程序开始监听PPPOE流量
3. 触发目标设备（本机、机顶盒或路由器）的PPPOE拨号
4. 成功捕获后会显示用户名和密码

### 离线分析模式

分析已保存的pcap抓包文件：

```bash
# 拖动pcap文件到程序图标上
# 或命令行执行
PPPOE.exe "capture.pcap"
```

### MAC地址模式

程序根据文件名自动选择MAC地址模式：

- **默认模式**（文件名不包含 `"zpf"`）：使用虚拟MAC地址 `01:01:01:02:02:02`
  - 通用性强，可用于获取本机宽带密码
  
- **真实MAC模式**（文件名包含 `"zpf"`，如 `PPPOEzpf.exe`）：使用本机网卡物理地址
  - 适用于直接连接目标设备的场景

### 网络连接方式

- **直接连接两机/机顶盒/路由器**：请使用**双机互联的网线**（交叉线）
- **局域网监听**：普通网线连接交换机即可

## 技术原理

### PPPOE协议流程

1. **发现阶段 (Discovery)**：
   - PADI (客户端广播寻找AC)
   - PADO (AC响应)
   - PADR (客户端请求连接)
   - PADS (AC确认，分配Session ID)

2. **LCP阶段 (Link Control Protocol)**：
   - 协商最大接收单元(MRU)、认证协议等参数
   - 本程序强制要求使用PAP明文认证

3. **PAP阶段 (Password Authentication Protocol)**：
   - 客户端发送用户名/密码
   - **程序在此阶段提取凭据**

### 核心组件

- **数据包捕获**: 使用WinPcap过滤以太网类型 `0x8863`（PPPOE发现）和 `0x8864`（PPPOE会话）
- **数据包注入**: 模拟AC发送响应包，引导客户端使用PAP认证
- **协议解析**: 解析PPPOE标签、LCP选项、PAP认证数据

## 输出结果

捕获成功后，程序会：

1. 在控制台显示：
   ```
   获得用户名和密码, 用户名: xxxxxx  密码: xxxxxx
   ```

2. 自动保存到程序目录下的 `PPPoE_帐号密码.txt` 文件

## 注意事项

1. **必须安装 WinPcap** 才能运行本程序
2. **需要管理员权限** 进行原始数据包捕获和注入
3. 网卡使用**混杂模式**接收所有流量
4. 仅支持**PAP明文认证**，不支持CHAP等加密认证
5. 程序使用硬编码的 Session ID `0x0311` 和 Magic Number `0x5e630ab8`
6. 代码注释和输出主要为中文

## 安全声明

**本工具仅供学习交流使用，请勿用于非法用途。**

- 仅应在您拥有合法权限的网络环境中使用
- 仅用于找回自己遗忘的密码或学习网络协议
- 非法使用造成的一切后果由使用者自行承担

## 技术细节

### 关键数据结构

```cpp
// 以太网头部（14字节）
ETHERNET_HEADER {
    u_char dmac[6];     // 目标MAC
    u_char smac[6];     // 源MAC
    u_short type;       // 以太网类型
}

// PPPOE头部（6字节）
PPPOED_HEADER {
    u_char pppoe_ver_type;    // 版本/类型
    u_char pppoe_code;        // 代码（PADI/PADO/PADR/PADS等）
    u_short pppoe_sessionid;  // 会话ID
    u_short pppoe_payload;    // 载荷长度
}

// PPP头部
PPP_HEADER {
    u_short protocol;   // 协议类型（LCP/PAP/CHAP等）
    u_char code;        // 代码
    u_char identifier;  // 标识符
    u_short length;     // 长度
}
```

### 依赖库

- `wpcap.lib` - WinPcap主库
- `Packet.lib` - 数据包处理库
- `ws2_32.lib` - Windows Socket库
- `Iphlpapi.lib` - IP Helper库

## 许可证

本软件遵循原作者的版权声明。

**版权所有 (C) 2008 zhupf (xzfff@126.com)**

本仓库仅作为历史代码的存档和学习资料发布，不声明任何额外的许可证。如有版权问题，请联系原作者或通知本仓库维护者下架。

---

*README 编写于 2025年4月*

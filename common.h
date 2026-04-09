// 定义测试使用的MAC
#ifndef _COMMON_
#define _COMMON_

#define TEST_MAC

#include <iostream>
#include <string>
#include <vector>
#include <pcap.h>

#include <winsock2.h>
#include <Iphlpapi.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
using namespace std;

#ifndef ETHERTYPE_PPPOED
#define ETHERTYPE_PPPOED	0x8863
#endif
#ifndef ETHERTYPE_PPPOES
#define ETHERTYPE_PPPOES	0x8864
#endif
#define PPPOE_HDRLEN 6

#define PADS_SESSION_ID		0x0311
#define PAP_AUTH			0xc023

enum PPPOE_STATUS {
	PPPOE_PADI = 0x09,
	PPPOE_PADO = 0x07,
	PPPOE_PADR = 0x19,
	PPPOE_PADS = 0x65,
	PPPOE_PADT = 0xa7
};

enum PPPOE_TAGS {
	END_OF_LIST			= 0x0000,
	SERVICE_NAME		= 0x0101,
	AC_NAME				= 0x0102,
	HOST_UNIQ			= 0x0103,
	AC_COOKIE			= 0x0104,
	VENDOR_SPECIFIC		= 0x0105,
	RELAY_SESSION_ID	= 0x0110,
	SERVICE_NAME_ERROR	= 0x0201,
	AC_SYSTEM_ERROR		= 0x0202,
	GENERIC_ERROR		= 0x0203 
};

enum PPP_STATUS {
	PPP_LCP  = 0xc021,
	PPP_PAP  = 0xc023,
	PPP_CHAP = 0xc223,
	PPP_CBCP = 0xc029,
	PPP_CCP  = 0x80fd,
	PPP_IPCP = 0x8021,
	PPP_COMP = 0x00fd
};

enum PPP_LCP_CODE {
	LCP_CREQ = 0x01,
	LCP_CACK = 0x02,
	LCP_CNAK = 0x03,
	LCP_CREJ = 0x04,
	LCP_TREQ = 0x05,
	LCP_TACK = 0x06,
	LCP_IDE  = 0x0c
};

enum PPP_LCP_OPT {
	OPT_MRU		= 0x01,
	OPT_AUTH	= 0x03,
	OPT_MAGNUM	= 0x05,
	OPT_CBACK	= 0x0d
};

enum PPP_PAP_CODE {
	PAP_AREQ = 0x01,
	PAP_AACK = 0x02,
	PAP_ANAK = 0x03
};

// not arp and not smb and not tcp
//typedef struct pcap_if eth

// 以太网首部
typedef struct _ETHERNET_HEADER{
    u_char dmac[6];
    u_char smac[6];
    u_short type;
}ETHERNET_HEADER, *PETHERNET_HEADER;

// PPPOED首部
typedef struct _PPPOED_HEADER{
    u_char pppoe_ver_type;
    u_char pppoe_code;
    u_short pppoe_sessionid;
    u_short pppoe_payload;
}PPPOED_HEADER, *PPPPOED_HEADER;

// PPPOE标签TAG
typedef struct _PPPOE_TAG{
    u_short tagName;
    u_short tagLen;
    u_char tagInfo;
}PPPOE_TAG, *PPPPOE_TAG;

// PPP首部
typedef struct _PPP_HEADER{
    u_short protocol;
    u_char code;
    u_char identifier;
    u_short length;
}PPP_HEADER, *PPPP_HEADER;

// PPP LCP的OPTION
typedef struct _LCP_OPT{
    u_char opt_code;
    u_char opt_len;
    u_char optInfo;
}LCP_OPT, *PLCP_OPT;
//-------------------------------
// 封包处理功能函数
//-------------------------------

// 取得本地的MAC地址
bool GetLoaclMac(int& idx);

// 根据收到的封包,创建PPPOE封包
void build_PPPOE_PACKET(PPPOE_STATUS status, const u_char *pkt_data);

// 创建PAP要求设置封包
void build_PAP_AUTH_CREQ_PACKET();

// 创建LCP设置回应封包
void build_LCP_ACK_PACKET(const u_char *pkt_data, bool bAck);

// 发送已经构造好的一个封包
bool SendPacket();

// 处理PPPOED发现阶段
void check_PPPOED(const u_char *pkt_data);

// 处理PPP连接阶段
void check_PPPOES(const u_char *pkt_data);

// 处理PAP身份验证阶段
void processPPP_PAP(PPP_PAP_CODE pap_code, const u_char *pkt_data);

// 处理LCP设置阶段
void processPPP_LCP(PPP_LCP_CODE lcp_code, const u_char *pkt_data);

// 分类处理接收的封包
void ProcessPktdata(const u_char *pkt_data);

// 记录用户名和密码到文件
void WriteInfoToFile();

// 根据程序文件名来决定使用的网卡物理地址
void UseMacByFileName();

// 获取键盘输入,得到选择的网卡号码
bool GetDeviceToUse(int& DeviceNbr);

// 等待退出
void wait2exit();

#endif
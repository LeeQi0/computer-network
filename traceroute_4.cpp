// traceroute_4.cpp : 定义控制台应用程序的入口点。
//
#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>


#define HAVE_REMOTE  
#include <pcap.h>
#include <remote-ext.h>

#define ETHER_ADDR_LEN 6
#define IP_ADDR_LEN 4

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

typedef struct{
u_char ver_hlen;
u_char tos;
u_short totallen;
u_short id;
u_short off;
u_char ttl;
u_char protocal;
u_short crc;
ipaddress srcip;
ipaddress destip;
}ip_header;

typedef struct 
{
  u_int16_t source;         /* source port */
  u_int16_t dest;   /* destination port */
  u_int16_t len;            /* udp length */
  u_int16_t checkl;         /* udp checksum */
}udp_header;

typedef struct{
	u_short data;
}data;

struct  ether_header{ 
 macaddress   ether_dhost;
 macaddress   ether_shost; 
 u_short   ether_type;  //如果上一层为IP协议。则ether_type的值就是0x0800
};


int main(int argc, char **argv)
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

	ether->ether_dhost.mac1=0x00;
	ether->ether_dhost.mac2=0x1a;
    ether->ether_dhost.mac3=0xa9;
    ether->ether_dhost.mac4=0x15;
    ether->ether_dhost.mac5=0x63;
	ether->ether_dhost.mac6=0x35;

	ether->ether_type=0x0800;
	
   
/********************************************************************/	
/*********************IP包头**********************/
    ip_header Ip_header;
	ip_header *ip=&Ip_header;
	ip->ver_hlen=0x45;
	ip->tos=0x00;
	ip->totallen=30;//30B
	ip->id=0x0000;
	ip->off=0x0000;
	ip->ttl=1;
	ip->protocal=17;
	ip->crc=0;

	ip->srcip.addr1=49;
    ip->srcip.addr2=140;
    ip->srcip.addr3=161;
	ip->srcip.addr4=172;

	ip->destip.addr1=49;
	ip->destip.addr2=140;
	ip->destip.addr3=161;
	ip->destip.addr4=254;

/****************************************************************/
/************************UDP包******************************/
	udp_header Udp_header;
	udp_header *udp=&Udp_header;
	udp->source=10;
	udp->dest=10000;
	udp->len=8;
	udp->checkl=0;

/********************************************************************/
/************************数据****************************/
	data Data;
	data* sj=&Data;
	sj->data=100;
/*******************************************************************/
/*************************加载packet***************************/
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

	packet[pkt++]=ip->ver_hlen;
	packet[pkt++]=ip->tos;
	packet[pkt++]=(u_char)(ip->totallen>>8);
    packet[pkt++]=(u_char)(ip->totallen);
	packet[pkt++]=(u_char)(ip->id>>8);
	packet[pkt++]=(u_char)(ip->id);
	packet[pkt++]=(u_char)(ip->off>>8);
	packet[pkt++]=(u_char)(ip->off);
	packet[pkt++]=ip->ttl;
	packet[pkt++]=ip->protocal;
	packet[pkt++]=(u_char)(ip->crc>>8);
	packet[pkt++]=(u_char)(ip->crc);
	packet[pkt++]=ip->srcip.addr1;
	packet[pkt++]=ip->srcip.addr2;
	packet[pkt++]=ip->srcip.addr3;
	packet[pkt++]=ip->srcip.addr4;
	packet[pkt++]=ip->destip.addr1;
	packet[pkt++]=ip->destip.addr2;
	packet[pkt++]=ip->destip.addr3;
	packet[pkt++]=ip->destip.addr4;
	packet[pkt++]=udp->source;
	packet[pkt++]=udp->dest;
	packet[pkt++]=udp->len;
	packet[pkt++]=udp->checkl;
	packet[pkt++]=(u_char)(sj->data>>8);
	packet[pkt++]=(u_char)(sj->data);
//	printf("%d",pkt);
	for(int i=0;i<pkt;i++)
//  		if(i<=11)
		   printf("%x  ",packet[i]);
//		else 
//		   printf("%d  ",packet[i]);
//	unsigned short a=0x4243;
//	printf("%x ",unsigned char(a>>8));



/*********************************************************************/

	/* Send down the packet */
	if (pcap_sendpacket(fp,	// Adapter
		packet,				// buffer with the packet
		100					// size
		) != 0)
	{
		
		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
		return 3;
	}
	printf("\nok\n");
	pcap_close(fp);	
	return 0;
}


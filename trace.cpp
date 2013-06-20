#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <iostream>
#include <fstream> 
#include <string>
#include <zlib.h>
#include <iconv.h>
#include <list>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h> // System setup need.
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/netfilter.h> // for NF_ACCEPT
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include <pthread.h>
#include <string.h>
#include <syslog.h>
#include <netinet/ip_icmp.h>
#include <setjmp.h>

using namespace std;
#define OK  0 

/* ICMP协议的值 */
static int PROTO_ICMP = -1;
/* 程序活动标志 */
static int alive = -1;
static int rawsock;

uint32_t defaultime  =  0;
uint32_t nodnum      =  0;
uint32_t sendlast    =  0;

typedef struct
{
	#if __BYTE_ORDER == __LITTLE_ENDIAN
		unsigned int ihl:4;
		unsigned int version:4;
	#elif __BYTE_ORDER == __BIG_ENDIAN
		unsigned int version:4;
		unsigned int ihl:4;
	#else
	#error	"Please fix <bits/endian.h>"
	#endif
} ip_version;


typedef  struct IPLIST{
	uint32_t uiaddr;
	uint32_t uimask; 
	float    ftime;
	struct IPLIST  *next;
}IPLIST,*p_IPLIST;


enum hook_mark
{
	HOOK_MARK_BEGIN,
	INPUT_MARK = 1,
	CONN_BYTES_MARK = 2,
	MATCH_REP_PLAIN_MARK = 3,
	MATCH_REP_GZIP_MARK = 4,
	HOOK_MARK_END
};

p_IPLIST gHead_Iplist =  NULL  ;
p_IPLIST gTail_Iplist =  NULL  ;


typedef struct
{
	uint32_t ipaddr;
	uint32_t i_pack_id;
	nfq_q_handle * qh;	
	
}packet_info_t;

#define htons32(addr)  ((addr&0xff000000)>>24)+((addr&0xff0000)>>8)+((addr&0xff00)<<8)+((addr&0xff)<<24)

uint16_t cal_chksum(uint16_t *add,int len)
{
	int nleft = len;
	uint32_t sum = 0;
	uint16_t *w = add;
	uint16_t check_sum = 0;

	while(nleft>1)		//
	{
		sum += *w++;
		nleft--;
	}

	if(nleft == 1)		//最后一个如果不够16bit，放在高位，后面补0
	{
		*(uint16_t *)(&check_sum) = *(uint16_t *)w;
		sum += check_sum;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum>>16);
	check_sum = (~sum)&0xFFFF;	
	return check_sum;
}
/*********************************************************************************
  *Function:  send_last_icmp
  *Description：根据IP地址所在的网段，执行相应的延时，默认15ms
  *Calls:  NULL
  *Called By:  thread_start
  *Input:  待延时的IP地址
  *Output:  NULL
  *Return:  延时结果
  *date:  2013-05-23
**********************************************************************************/
static void send_last_icmp ( struct iphdr * ip_header, struct udphdr *udp_header, uint8_t * copy )
{ 
    struct sockaddr_in to; 
    struct iphdr    *iph   = NULL; 
    struct icmp     *icmph = NULL; 
	struct iphdr    *udpip = NULL; 
	struct udphdr   *udpudp = NULL; 
	uint8_t  *copybyte = NULL; 
	uint8_t  *copyloop = NULL; 
    char  *packet  = NULL; 
	int   cloop    = 0;
    uint32_t sum = 0;
    int pktsize = (ip_header->tot_len>>8)+sizeof(iphdr)+sizeof(icmph); 
	
    packet =(char *)malloc (pktsize); 
	memset (packet, 0, pktsize); 
	
    iph    = (struct iphdr *) (packet) ; 
    icmph  = (struct icmp *)  (packet + sizeof(iphdr)); 
	udpip  = (struct iphdr *) (packet+sizeof(iphdr)+sizeof(icmph)) ; 
	udpudp = (struct udphdr *) (packet+sizeof(iphdr)+sizeof(icmph)+sizeof(iphdr)) ; 
	copybyte   = (uint8_t *) (packet + sizeof(iphdr)+sizeof(icmph)+sizeof(iphdr)+sizeof(udphdr)); 
	
   
    /* IP的版本,IPv4 */
    iph->version = 4; 
    /* IP头部长度,字节数 */
    iph->ihl = 5; 
    /* 服务类型 */
    iph->tos = 0xc0; 
    /* IP报文的总长度 */
    iph->tot_len = htons (pktsize); 
    /* 标识,设置为PID */
	//iph->id //不填会自动填充
    /* 段的便宜地址 */
    iph->frag_off = 0;
    /* TTL */
    iph->ttl = 0x40-ip_header->ttl+1; 
    /* 协议类型 */
    iph->protocol = PROTO_ICMP; 
    /* 校验和,先填写为0xb0af */
    //iph->check  //不填会自动填充
    /* 发送的源地址 */
    iph->saddr = ip_header->daddr;     
    /* 发送目标地址 */
    iph->daddr = ip_header->saddr;
	
	
	
    /* ICMP类型为端口不可达 */
    icmph->icmp_type = ICMP_UNREACH;  
    /* 代码为0 */
    icmph->icmp_code = ICMP_UNREACH_PORT; 
	icmph->icmp_seq = 0;
    /* 校验和先置为0，后面计算 */
	icmph->icmp_cksum = 0;
	
	
	/* 拷贝请求报文的IP头 */
	/* IP的版本,IPv4 */
    udpip->version = ip_header->version; 
    /* IP头部长度,字节数 */
    udpip->ihl = ip_header->ihl ; 
    /* 服务类型 */
    udpip->tos = ip_header->tos; 
    /* IP报文的总长度 */
    udpip->tot_len = ip_header->tot_len ; 
    /* 标识,设置为PID */
    udpip->id = ip_header->id;
	
    /* 段的便宜地址 */
    udpip->frag_off = ip_header->frag_off;
    /* TTL */
    udpip->ttl = 1; 
    /* 协议类型 */
    udpip->protocol = ip_header->protocol; 
    udpip->check = 0 ; //重新计算！！！
    /* 发送的源地址 */
    udpip->saddr = ip_header->saddr ;     
    /* 发送目标地址 */
    udpip->daddr = ip_header->daddr;
	udpip->check =  cal_chksum((uint16_t *)udpip,sizeof(iphdr)/2) ;
	
	
	udpudp->source = udp_header->source;
	udpudp->dest   = udp_header->dest;
	udpudp->len    = udp_header->len;
	udpudp->check  = 0;
		
	
	//copy 剩下的字节
	for(cloop = 0; cloop < (ip_header->tot_len>>8)-sizeof(iphdr)-sizeof(udphdr);cloop++)
	{
		*copybyte++ = *copy++;
	}
	
	
	
	
    /* 填写发送目的地址部分 */
    to.sin_family =  AF_INET; 
    to.sin_addr.s_addr = ip_header->saddr;
    to.sin_port = htons(0);
	icmph->icmp_cksum = cal_chksum((uint16_t *)icmph,(pktsize - sizeof(iphdr))/2) ;
	printf("last hop  source is : %x ,dest addr is %x \n", ip_header->daddr,ip_header->saddr);
    /* 发送数据 */
    sendto(rawsock, packet, pktsize, 0, (struct sockaddr *) &to, sizeof (struct sockaddr)); 
    /* 释放内存 */
	
    free (packet);
}
/*********************************************************************************
  *Function:  send_mid_icmp
  *Description：根据IP地址所在的网段，执行相应的延时，默认15ms
  *Calls:  NULL
  *Called By:  thread_start
  *Input:  待延时的IP地址
  *Output:  NULL
  *Return:  延时结果
  *date:  2013-05-23
**********************************************************************************/
static void send_mid_icmp( struct iphdr * ip_header, uint32_t saddr ,struct udphdr *udp_header, uint8_t * copy)
{ 
    struct sockaddr_in to; 
    struct iphdr  *iph   = NULL; 
    struct icmp   *icmph = NULL; 
	struct iphdr  *udpip = NULL;
	struct udphdr *udp   = NULL;
    char *packet = NULL; 
	int   cloop = 0;
	
	uint8_t  *copybyte = NULL;
	uint8_t  *copyloop = NULL;
    uint32_t sum = 0;
    int pktsize = (ip_header->tot_len>>8)+sizeof(iphdr)+sizeof(icmph); 
    packet = (char *)malloc (pktsize); 
	memset (packet, 0, pktsize); 
	
	
	
	
	p_IPLIST TraceLoop   = NULL;
    iph      = (struct iphdr *)(packet) ; 
    icmph    = (struct icmp  *)(packet + sizeof(iphdr)); 
	udpip    = (struct iphdr *)(packet + sizeof(iphdr)+sizeof(icmph)); 
	udp      = (struct udphdr *) (packet + sizeof(iphdr)+sizeof(icmph)+sizeof(iphdr)); 
	copybyte = (uint8_t *) (packet + sizeof(iphdr)+sizeof(icmph)+sizeof(iphdr)+sizeof(udphdr)); 
	
    /* IP的版本,IPv4 */
    iph->version = 4; 
    /* IP头部长度,字节数 */
    iph->ihl = 5; 
    /* 服务类型 */
    /* IP报文的总长度 */
    iph->tot_len = htons (pktsize); 
    /* 标识,设置为PID */
    // iph->id //自动填充
    /* 段的偏移地址 */
    iph->frag_off = 0;
    /* TTL */
    iph->ttl = 0x40-ip_header->ttl+1; 
	
	//只有跟发起端直连的下一跳，这里才是0
	if(iph->ttl == 0xff)
	{
		iph->tos = 0xc0;
	}
	else
	{
		iph->tos = 0x0;
	}
    /* 协议类型 */
    iph->protocol = PROTO_ICMP; 
    /* 校验和,自动填充 */
	//iph->check 
    /* 发送的源地址 */
    iph->saddr = saddr; 
    /* 发送目标地址 */
    iph->daddr = ip_header->saddr;
	
	
    /* ICMP类型为超时 */
	icmph->icmp_type = ICMP_TIMXCEED;  
    /* 代码为0 */
    icmph->icmp_code = ICMP_TIMXCEED_INTRANS; 
	icmph->icmp_seq = 0;
	
	
	/* IP的版本,IPv4 */
    udpip->version = ip_header->version;  
    /* IP头部长度,字节数 */
    udpip->ihl = ip_header->ihl ;  
    /* 服务类型 */
    udpip->tos = ip_header->tos;  
    /* IP报文的总长度 */
    udpip->tot_len = ip_header->tot_len;  
    /* 标识,设置为PID */
    udpip->id =ip_header->id;
    /* 段的便宜地址 */
    udpip->frag_off = ip_header->frag_off; 
    /* TTL */
	udpip->ttl = 1;
    /* 协议类型 */
    udpip->protocol = ip_header->protocol;    
    /* 校验和 */
    udpip->check = 0;
	
    /* 发送的源地址 */
    udpip->saddr = ip_header->saddr ;    
    /* 发送目标地址 */
    udpip->daddr = ip_header->daddr;     
	udpip->check =  cal_chksum((uint16_t *)udpip,sizeof(iphdr)/2) ;
	

	udp->source = udp_header->source;
	udp->dest   = udp_header->dest;
	udp->len    = udp_header->len;
	udp->check  = udp_header->check;
	
	
	for( cloop = 0;cloop < ((ip_header->tot_len)>>8)-sizeof(iphdr)-sizeof(udphdr); cloop++ )
	{
		
		*copybyte++ = *copy++;
		
	} 
	

	
    /* 填写发送目的地址部分 */
    to.sin_family =  AF_INET; 
    to.sin_addr.s_addr = ip_header->saddr;
    to.sin_port = htons(0);
	
	/* 计算icmp报文校验和 */
	icmph->icmp_cksum = cal_chksum((uint16_t *)icmph,(pktsize - sizeof(iphdr))/2) ;
	printf("the source is : %x ,dest addr is %x \n", saddr,ip_header->saddr);
    /* 发送数据 */
    sendto(rawsock, packet, pktsize, 0, (struct sockaddr *) &to, sizeof (struct sockaddr)); 
    /* 释放内存 */
	
    free (packet);
}


/*********************************************************************************
  *Function:  get_packet_id
  *Description：获取包Id并返回
  *Calls:  NULL
  *Called By:  input_handler
  *Input:  待延时的报文属性tb
  *Output:  NULL
  *Return:  pkt_id
  *date:  2013-05-23
**********************************************************************************/
u_int32_t get_packet_id ( struct nfq_data *tb )
{
	u_int32_t pkt_id = 0;
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
	if(ph)
	{
		pkt_id = ntohl(ph->packet_id);
	}
	return pkt_id;
}

/*********************************************************************************
  *Function:  input_handler
  *Description：回调函数
  *Calls:  NULL
  *Called By:  input_handler
  *Input:  待处理的报文属性
  *Output:  NULL
  *Return:  pkt_id
  *date:  2013-06-14
**********************************************************************************/
uint32_t input_handler( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data)
{
	//first judge ipv4 or ipv6
	uint32_t id_packet   = get_packet_id(nfa);
	uint32_t i_mark      = nfq_get_nfmark(nfa);
	uint32_t uiRet       = 0;
	uint32_t num         = 0;
	uint32_t flag        = 0;
	uint32_t ttloop      = 0;
	uint32_t cloop       = 0;
	uint32_t sum       = 0;
	uint8_t   * copy   = NULL;
	uint8_t   * cp     = NULL;
	uint8_t   * cploop = NULL;
	p_IPLIST TraceLoop   = NULL;
	struct udphdr *udp = NULL;
	if( i_mark != INPUT_MARK )
	{
		nfq_set_verdict(qh,id_packet,NF_ACCEPT,0,NULL);
		return id_packet;
	}
	
	unsigned char * ip_payload_data = NULL;
	int i_payload_len = nfq_get_payload(nfa,&ip_payload_data);
	if( -1 == i_payload_len )
	{
		nfq_set_verdict( qh,id_packet,NF_ACCEPT,0,NULL );
		return id_packet;
	}
	
	ip_version * p_version = (ip_version*)(ip_payload_data);
	if( 4 != p_version->version )
	{
		nfq_set_verdict( qh,id_packet,NF_ACCEPT,0,NULL );
		return id_packet;
	}
	
	struct iphdr * ip_header = (iphdr*)(ip_payload_data);
	
	if(  ip_header->protocol == IPPROTO_UDP )
	{	
		udp   = (struct udphdr *) (ip_payload_data + sizeof(iphdr)); 
		copy  = (uint8_t *)(ip_payload_data + sizeof(iphdr)+sizeof(udphdr));
		
		ttloop = ip_header->ttl-1; 
		if(ttloop > nodnum || ip_header->ttl>nodnum+1)
		{
			nfq_set_verdict(qh,id_packet,NF_ACCEPT,0,NULL);
			return id_packet;
		}
		TraceLoop = &(*gHead_Iplist);
	
		while( TraceLoop != NULL && ttloop-- )
		{
				TraceLoop = TraceLoop->next;
		}
		
		nfq_set_verdict( qh,id_packet,NF_DROP,0,NULL );
		
		
	
	
		printf("ip_header->ttl = %d nodnum is %d  \n",ip_header->ttl,nodnum);
		if( ip_header->ttl <= nodnum)
		{
			usleep(TraceLoop->ftime*1000);
			send_mid_icmp(ip_header,htons32(TraceLoop->uiaddr),udp,copy);

		}
		else if(ip_header->ttl== nodnum+1)
		{
			send_last_icmp(ip_header,udp,copy);
			sendlast++;
			if(sendlast == 3)
			{
				sendlast =  0;
			}
		}
		
	}
	return id_packet;
}


static int main_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data)
{
	u_int32_t id_packet = get_packet_id(nfa);
	uint32_t i_mark = nfq_get_nfmark(nfa);
	if( i_mark  == INPUT_MARK )
	input_handler(qh,nfmsg,nfa,data);
	else
	{
		nfq_set_verdict( qh,id_packet,NF_ACCEPT,0,NULL );
	}
	
	return id_packet;
}

/*********************************************************************************
  *Function:  Str_to_Num
  *Description：将从数据库中获取的字符串形式的IP地址，转化成32bit的无符号整数
  *Calls:  NULL
  *Called By:  Get_Insert_Joint_IP
  *Input:  从数据库中获取的字符串形式的IP地址
  *Output:  NULL
  *Return:  IP地址对应的32bit的无符号整数
  *date:  2013-02-22
**********************************************************************************/
uint32_t Str_to_Num ( string st ) 
{
	uint32_t uiWord  = 0;
	uint32_t uiBlock = 0;	
	uint32_t uiLoop  = 0;
	while( uiLoop < st.size() )
	{
		uiWord = 0;
		if(st[uiLoop] <'0'||st[uiLoop] >'9')
		{
		/* 如果取到的不是0~9的数字，取下一个 */  
			uiLoop++;
		}
		else
		{
			/* 计算IP地址，放到uiBlock中 */  
			while( st[uiLoop]>='0' && st[uiLoop]<='9' )
			{
				uiWord = uiWord* 10 + st[uiLoop]-'0';
				uiLoop++;
			}
			
			uiBlock = (uiBlock<<8) + uiWord;
		}
	}
	return uiBlock;
}
/*********************************************************************************
  *Function:  Insert_addr
  *Description：将列表中的地址和对应延时添加到链表中，作为后续做延时的依据
  *Calls:  NULL
  *Called By:  Get_Insert_Joint_IP
  *Input:  从iplist.txt中获取的IP地址和延时
  *Output:  NULL
  *Return:  延时关系链表
  *date:  2013-02-22
**********************************************************************************/
uint32_t Insert_addr( p_IPLIST *pstHead,p_IPLIST *psTail,uint32_t uiIpaddr,uint32_t uiMask,float tm)
{
	//修改算法，如果比当前节点的值大，则往后遍历找位置，比当前小的从头遍历找位置，插入后返回插入位置，为下一次插入做比较基准
	uint32_t uiLtemp 	   = 0;
	uint32_t uiLtempmask   = 0;
	uint32_t uiLtemptime  = 0;
	p_IPLIST pstmp   = NULL;
	p_IPLIST pstHsek = NULL;
	p_IPLIST pstHtil = NULL;
	
	pstHtil = *psTail ;
	/*新申请节点 */  
	pstmp = new IPLIST ;
	if( pstmp == NULL )
	{
		#ifdef DEBUG
		printf("sorry,failed to malloc mem pstmp == NULL!!\n");
		#endif
		return OK;
	}
		
		
	if( *pstHead == NULL )
	{
		/* 如果还没有节点，则新增节点，入参放到新增节点中去 */  
		pstmp->next = NULL;
		*psTail  = pstmp;
		*pstHead = pstmp;
		pstmp->uiaddr = uiIpaddr ;
		pstmp->uimask = uiMask ;
		pstmp->ftime  = tm  ;
		return OK;
	}
		
	/* 如果入参比末尾节点大，则新增节点，入参放到新增节点中去 */  
	pstmp->next = NULL;
	pstHtil->next = pstmp;
	
	*psTail = pstmp;
		
	pstmp->uiaddr = uiIpaddr;
	pstmp->uimask = uiMask;
	pstmp->ftime  = tm  ;
	return OK;
	
}


int main( int argc, char *argv[] )
{
	uint32_t    uiRet  = 0;
	uint32_t    mask   = 0;
	uint32_t    uiIP   = 0;
	float  ftime = 0;
	int i_queue_num = 1;
	string ipaddr;
	p_IPLIST pDel             = NULL;
	p_IPLIST ploop            = NULL;
	
	struct hostent * host     = NULL;
    struct protoent *protocol = NULL;
    char protoname[]= "icmp";
 
    int i = 0;
    int err = -1;
    unsigned long  temp;
	
	if(argc != 1)
	{
		printf("please input ./trace  *default delay time(ms)*\n");
		return 0;
	}
	/* 获取协议类型ICMP */
    protocol = getprotobyname(protoname);
    if (protocol == NULL)
    {
        perror("getprotobyname()");
        return -1;
    }
    PROTO_ICMP = protocol->p_proto;
	
    /* 建立原始socket */
    rawsock = socket (AF_INET, SOCK_RAW, PROTO_ICMP);  
    if (rawsock < 0)      
        rawsock = socket (AF_INET, SOCK_RAW, PROTO_ICMP);  
 
    /* 设置IP选项 */
    setsockopt (rawsock, SOL_IP, IP_HDRINCL, "1", sizeof ("1"));
	
	
	
	//int itime = 0;
	//sscanf(argv[1],"%d",&itime);
	//defaultime = itime;
	
	struct nfq_handle *  handler = nfq_open();
	if (!handler)
	{
		exit(1);
	}

	if ( nfq_unbind_pf(handler, AF_INET) < 0 )
	{
		exit(1);
	}

	if ( nfq_bind_pf( handler, AF_INET) < 0 )
	{
		exit(1);
	}
	
	
	fstream Fplist;
	Fplist.open("trace.txt",ios::in);
	if(!Fplist)
	{ 
		cout<<"can not open trace.txt\n"; 
		return -1;
	} 
	
	while( Fplist >> ipaddr )
	{
		Fplist >> mask;
		Fplist >> ftime;
		uiIP  =  Str_to_Num ( ipaddr );
		uiRet = Insert_addr( &gHead_Iplist,&gTail_Iplist,uiIP,mask,ftime);
		nodnum++;
	}
		
	struct nfq_q_handle *qh = NULL;
	qh = nfq_create_queue(handler, i_queue_num, &main_handler, NULL);
	if (!qh)
	{
		exit(1);
	}
	
	if ( nfq_set_mode( qh, NFQNL_COPY_PACKET, 0xffff ) < 0)
	{
		exit(1);
	}

	if( nfq_set_queue_maxlen( qh,0xffffffff ) < 0 )
	{
		exit(1);
	}

	int fd = nfq_fd(handler);
		
	char buf[4096] __attribute__ ((aligned));
	int rv = -1;
	
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
	{
		
		nfq_handle_packet(handler, buf, rv);
		
	}

	ploop = &(*gHead_Iplist);

	while( ploop != NULL )
	{
		pDel = ploop;
		ploop = ploop->next;
		free( pDel );
		pDel = NULL;
	}
	printf("over \n");
    close(rawsock);
	nfq_destroy_queue(qh);
	nfq_close(handler);
	Fplist.close();
	return 0;
}

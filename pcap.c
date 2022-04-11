#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>
#include <arpa/inet.h>
#define BUFSIZE 10240
#define STRSIZE 1024

typedef int bpf_int32;
typedef unsigned int bpf_u_int32;
typedef unsigned short u_short;
typedef unsigned int u_int32;
typedef unsigned short u_int16;
typedef unsigned char u_int8;

//pcap file structure
struct pcap_file_header
{
    bpf_u_int32 magic; //大小端
    u_short version_major;//版本号
    u_short version_minor;
    bpf_int32 thiszone;//本地标准时间
    bpf_u_int32 sigfigs;//时间戳精度
    bpf_u_int32 snaplen;//最大存储长度
    bpf_u_int32 linktype;//链路类型 
    /* data */
};

//packet header structure
struct pcap_packet_header
{
    int tv_sec;//高位时间 单位 秒
    int tv_msec;//地位时间 单位 ms
    bpf_u_int32 caplen;//当前packet的数据长度
    bpf_u_int32 len;//实际长度一般相等
    /* data */
}pcap_packet_header;

//以太帧header
typedef struct frame_header{//没有帧结束符
    u_int8 Dmac[6];//6B目的mac
    u_int8 Smac[6];//6B源mac
    u_short frametype;//2B高层协议类型，0800ip协议帧，0806arp协议帧
}frame_header;

//ip packet header
typedef struct ip_header
{
    u_int8 ver_len;//4bit version+4 bit header length
    u_int8 tos;//type of service
    u_int16 total_len;//整个报文的长度
    u_int16 id;//标识号，分段使用
    u_int16 flag_segment; //分段标志3bit  0x80-保留字段 0x40-不分段 0x20-更多分段 13bit 偏移量*8
    u_int8 ttl;
    u_int8 protocol;//协议报文 1-icmp 2-igmp 6-tcp 17-udp 89-ospf
    u_int16 hchecksum;//校验和
    u_int32 s_ip;//源ip
    u_int32 d_ip;//目的ip
    /* data */
}ip_header;

//tcp header
typedef struct tcp_header{
    u_int16 s_port;//源端口
    u_int16 d_port;//目的端口
    u_int32 seq_no;//序号
    u_int32 ack_no;//确认号 分段重组的关键
    u_int8 header_len;//4bit tcp_header长度 *4
    u_int8 flags;//标识tcp不同的控制消息
    u_int16 window;//窗口大小
    u_int16 checksum;//校验和
    u_int16 urgent_pointer;//紧急指针
}tcp_header;

//dns协议域名解析是udp报文
//udp header
typedef struct udp_header{
    u_int16 s_port;//源端口
    u_int16 d_port;//目的端口
    u_int16 len;//整个包的大小单位B
    u_int16 checksum;//
}udp_header;

//icmp报文header
typedef struct icmp_header{
    u_int8 b_type;
    u_int8 b_code;
    u_int16 checksum;
    u_int16 id;
    u_int16 seq;
    u_int32 timestamp;
}icmp_header;
//
typedef struct dns_header{
    u_int16 id;
    u_int16 flags;
    u_int16 question;
    u_int16 answerRR;
    u_int16 authorityRR;
    u_int16 additionalRR;
}dns_header;
//tls 头文件
typedef struct tls_header
{
    u_int8 content_type;
    u_int8 version[2];
    u_int8 len[2];//报文之后的长度
    /* data */
}tls_header;
typedef struct hand_header{
    u_int8 hands_type;
    u_int8 hands_len[3];
}hand_header;
enum tcp_flags{
    SYN=2,RST=4,FIN_ACK=17,SYN_ACK=18,ACK=16,PSH_ACK=24
}tcpFlag;
char *tcpFlags[]={"","","SYN","","RST","","","","","","","","","","","","ACK","FIN_ACK","SYN_ACK","","","","","","PSH_ACK"};
void match_http(FILE *fp, char *header_str, char *tail_str, char *buf, int total_len);
//
int main(){
    struct pcap_file_header *fileHeader;
    struct pcap_packet_header *packetHeader;
    ip_header *ipHeader;
    tcp_header *tcpHeader;
    udp_header *udpHeader;
    icmp_header *icmpHeader;
    dns_header *dnsHeader;
    tls_header *tlsHeader;
    hand_header *handHeader;
    FILE *fp, *output;
    int packet_offset, i = 0,pos=0;
    int ip_len, http_len, ip_proto,tcp_data_len;
    int src_port, dst_port, tcp_flags;
    char buf[BUFSIZE], my_time[STRSIZE];
    char src_ip[STRSIZE], dst_ip[STRSIZE];
    char host[STRSIZE], contentype[BUFSIZE],user_agent[BUFSIZE],cert[BUFSIZE];

    fileHeader = (struct pcap_file_header *)malloc(sizeof(struct pcap_file_header));
    packetHeader = (struct pcap_packet_header *)malloc(sizeof(struct pcap_packet_header));
    ipHeader = (ip_header *)malloc(sizeof(ip_header));
    tcpHeader = (tcp_header *)malloc(sizeof(tcp_header));
    udpHeader =(udp_header *)malloc(sizeof(udp_header));
    dnsHeader =(dns_header *)malloc(sizeof(dns_header));
    tlsHeader =(tls_header *)malloc(sizeof(tls_header));
    handHeader =(hand_header *)malloc(sizeof(hand_header));

    memset(buf, 0, sizeof(buf));
    if((fp=fopen("shaixuan.pcap","r"))==NULL){
        printf("error:can not open pcap file\n");
        exit(0);
    }
    packet_offset = 24;
    while(fseek(fp,packet_offset,SEEK_SET)==0){
        i++;
	//printf("%ld\n",sizeof(pcap_packet_header));
        if(fread(packetHeader,sizeof(pcap_packet_header),1,fp)!=1){
            printf("\n read end of pcap file");
            break;
        }
        packet_offset += 16 + packetHeader->caplen;
        //以太帧报文头
        fseek(fp, 14, SEEK_CUR);
        //ip帧报文头
        if(fread(ipHeader,sizeof(ip_header),1,fp)!=1){
            printf("%d:can not read ip_header\n",i);
            break;
        }
        inet_ntop(AF_INET, (void *)&(ipHeader->s_ip), src_ip, 16);
        inet_ntop(AF_INET, (void *)&(ipHeader->d_ip), dst_ip, 16);
        ip_proto = ipHeader->protocol;
        ipHeader->total_len=ntohs(ipHeader->total_len);
        ip_len = ipHeader->total_len;
        if(ip_proto==0x06){//tcp协议的地方
            if(fread(tcpHeader,sizeof(tcp_header),1,fp)!=1){
               printf("%d: can not read tcp_header\n", i);
               break;
            }
	    tcpHeader->header_len=tcpHeader->header_len>>4;
        tcp_data_len=ip_len-20-tcpHeader->header_len*4;
        src_port = ntohs(tcpHeader->s_port);
        dst_port = ntohs(tcpHeader->d_port);
        tcp_flags = tcpHeader->flags;
	    printf("%d: protocol:tcp src=%s:%d dst=%s:%d header length:%d  tcp flags:%s\r\n", i, src_ip, src_port,dst_ip, dst_port,tcpHeader->header_len*4,tcpFlags[tcp_flags]);
        if(tcp_flags==0x18&&(dst_port==80||src_port==80)){//握手成功
                //get 请求
            http_len = htons(ip_len) - 20-tcpHeader->header_len*4*16;
            match_http(fp, "Host", "\r\n", host, http_len);
		    match_http(fp, "Content-Type: ", "\r\n", contentype, http_len);
            match_http(fp,"User-Agent: ","\r\n",user_agent,http_len);
		    //match_http(fp, "POST", "HTTP",
		    printf("host:");
            int j=0;
            while(host[j]!=0){
			    if(host[j]<33||host[j]>128){
			        j++;
			        continue;}
                else{
			        printf("%c",host[j]);}
                    j++;
                    }
                printf("\ncontentype:  ");
                while(contentype[j]!=0){
                    if(contentype[j]<33||contentype[j]>128)
			        {
			            printf("%d",contentype[j]);
			        }
                    else
			        {
			            printf("%c",contentype[j]);
                    }
                    j++;
                }
                printf("\nUser-Agent:\t");
                j=0;
                while(user_agent[j]!=0){
                    if(user_agent[j]<33||user_agent[j]>128){
                        printf("%d",user_agent[j]);
                    }else{
                        printf("%c",user_agent[j]);
                    }
                    j++;
                }
                printf("\n");       
            }
        else if(tcp_data_len>0&&(dst_port==443||src_port==443))
            {//tls应用协议
                char c;
                for(int j=0;j<tcpHeader->header_len*4-20;j++){
                c=getc(fp);//遍历tcp头的额外的内容
                }
                if(fread(tlsHeader,sizeof(tls_header),1,fp)!=1){
                    printf("%d: can not read tls_header\n",i);
                    break;
                }
                if(dst_port==443&&tlsHeader->content_type==22){//读个数 读cipher 读server name
                    int tls_len=tlsHeader->len[0]*256+tlsHeader->len[1];
                    int hand_len=0;
                    //hand_len+=4+handHeader->hands_len[0]*256*256+handHeader->hands_len[1]*256+handHeader->hands_len[2];
                    while(tls_len-hand_len>0){
                        if(fread(handHeader,sizeof(hand_header),1,fp)!=1){
                            printf("%d: can not read hand_header\n",i);
                            break;
                        }
                        hand_len+=4+handHeader->hands_len[0]*256*256+handHeader->hands_len[1]*256+handHeader->hands_len[2];
                        //把里面加进去
                        if(handHeader->hands_type==1){
                            for(int j=0;j<34;j++){
                                getc(fp);
                            }
                            c=getc(fp);
                            for(int j=0;j<c;j++){
                                getc(fp);
                            }
                            int cipher_len=getc(fp)*256+getc(fp);
                            printf("Client hello:\t");
			                char cipher[2];
		    	            printf("client cipher suite:");
		    	            for(int j=0;j<cipher_len/2;j++){
			                    cipher[0]=getc(fp);
			                    cipher[1]=getc(fp);
			                    printf("no.%d: %04x  ",j+1,cipher[0]*256+cipher[1]);		
		                    }
		                    printf("\n");
                            c =getc(fp);
                            for(int j=0;j<c;j++){
                                getc(fp);
                            }
                            int len =getc(fp)*256+getc(fp);    
                            for(int j=0;j<len;j++){//加载extension
                                int type=getc(fp)*256+getc(fp);
                                j+=2;
                                int ext_len=getc(fp)*256+getc(fp);
                                j+=2;
                                if(type==0)//dengyu server_name
                                {
                                    printf("Server name:");
                                    if(ext_len!=0){
                                        for(int k=0;k<5;k++,j++)
                                            getc(fp);
                                        for(int k=0;k<ext_len-5;k++,j++){
                                            c=getc(fp);
                                            printf("%c",c);
                                        }
                                    }
                                    printf("\n");
                                    break;
                                }
                                for(int k=0;k<ext_len;k++,j++){
                                    getc(fp);
                                }
                            }  
                        }
                    }   
                }
                else if(src_port==443&&tlsHeader->content_type==22){ 
                    int tls_len=tlsHeader->len[0]*256+tlsHeader->len[1];
                    int hand_len=0;
                    while(tls_len-hand_len>0){
                        if(fread(handHeader,sizeof(hand_header),1,fp)!=1){
                            printf("%d: can not read hand_header\n",i);
                            break;
                        }
                        hand_len+=4+handHeader->hands_len[0]*256*256+handHeader->hands_len[1]*256+handHeader->hands_len[2];
                        if(handHeader->hands_type==2){//读cipher
                            for(int j=0;j<34;j++){//如果是serverhello，需要都
                                c=getc(fp);
                                //pos+=sprintf(cert+pos,c);
                            }
                            c=getc(fp);
                            for(int j=0;j<c;j++){
                                getc(fp);
                            }
                            printf("Server hello\t");
			                char cipher[2];
		    	            printf("server cipher suite:");
			                cipher[0]=getc(fp);
			                cipher[1]=getc(fp);
			                printf("server response cipher: %04x \n",cipher[0]*256+cipher[1]);		
                            c=getc(fp); 
                            int len =getc(fp)*256+getc(fp);    
                            for(int j=0;j<len;j++){//加载extension
                                int type=getc(fp)*256+getc(fp);
                                j+=2;
                                int ext_len=getc(fp)*256+getc(fp);
                                j+=2;
                                if(type==0)//dengyu server_name
                                {
                                    printf("Server name:");
                                    if(ext_len!=0){
                                        for(int k=0;k<5;k++,j++)
                                            getc(fp);
                                        for(int k=0;k<ext_len-5;k++,j++){
                                            c=getc(fp);
                                            printf("%c",c);
                                        }
                                    }                                  
                                    printf("\n");
                                    break;
                                }
                                for(int k=0;k<ext_len;k++,j++){
                                    getc(fp);
                                }
                            }               
                        } 
                        /*else if(handHeader->hands_type==11){
                            int len=getc(fp)*256*256+getc(fp)*256+getc(fp);
                            for(int j=0;j<len;j++){//循环读取certificates
                                int clen=getc(fp);
                                j++;
                                for(int k=0;k<2;k++,j++){
                                    c=getc(fp);
                                    clen=clen*256+c;
                                }
                                printf("%d  %d",len,clen);
                                printf("certificate:");
                                for(int k=0;k<clen;k++,j++){
                                    c=getc(fp);
                                    printf("%02x",c);
                                }
                                printf("\n");
                            }
                            break;    
                        }
                        else{//遍历hand内容
                            int len=handHeader->hands_len[0]*256*256+handHeader->hands_len[1]*256+handHeader->hands_len[2];
                            for(int j=0;j<len;j++){
                                getc(fp);
                            }
                        }*/
                    }
                    
                }
            }
        }
        else if(ip_proto==0x11){//udp协议报文
            if(fread(udpHeader,sizeof(udp_header),1,fp)!=1){
                printf("%d: can not read udp_header\n", i);
               break;
            }
            src_port=ntohs(udpHeader->s_port);
            dst_port=ntohs(udpHeader->d_port);
            udpHeader->len=ntohs(udpHeader->len);
            if(dst_port==53||src_port==53){//dns 协议报文
                printf("%d: protocol:dns src=%s:%d dst=%s:%d\r\n", i, src_ip, src_port,dst_ip, dst_port);
                if(fread(dnsHeader,sizeof(dns_header),1,fp)!=1){
                    printf("%d: can not read dns_header\n",i);
                    break;
                }
                int dns_data_len=udpHeader->len-sizeof(dns_header)-sizeof(udp_header);//全翻译出来
                if(src_port==53){
                    char c;
                    int eof=0;
		            int j=0;
                    while(j<dns_data_len){
                        c=getc(fp);
                        if(c<33){
                            if(eof==1&&c==4){
                                for(int x=0;x<4;x++){
                                    j++;
                                    c=getc(fp);
                                    printf("%d:",(c+256)%256);
                                }
                                eof=0;
                            }else{
                                if(c==0){
                                    eof=1;
                                    printf(".");
                                }else
                                {
                                    printf(".");
                                }
                            }
                        }
                        else if(c>32&&c<128){
                            printf("%c",c);
                        }else{
                            printf(".");
                        }
			        j++;
                            
                    }
			    printf("\n");       
                }
                else{
                    char c;
		            int j=0;
                    while(j<dns_data_len){
                        c=getc(fp);
                        if(c<33)
                            printf(".");
                        else{
                            printf("%c",c);
                        }
                        j++;
                    }
                    printf("\n");
                }
		        
            }else if(dst_port==443||src_port==443){//QUIC 的 Initial 包的初始机密（Initial secrets）同版本号，目标 Connection ID 相关，加密算法固定为 AES-128-GCM
                printf("%d: protocol:quic src=%s:%d dst=%s:%d\r\n", i, src_ip, src_port,dst_ip, dst_port);
            }

        }
    }
    fclose(fp);
    return 0;
}

void match_http(FILE *fp ,char*head_str,char *tail_str,char *buf,int total_len){
    int i;
    int http_offset;
    int head_len, tail_len, val_len;
    char head_tmp[STRSIZE], tail_tmp[STRSIZE];
    //start
    int ishead=0;
    memset(head_tmp, 0, sizeof(head_tmp));
    memset(tail_tmp, 0, sizeof(tail_tmp));
    head_len = strlen(head_str);
    tail_len = strlen(tail_str);
    // find head_str
    http_offset = ftell(fp);
    while((head_tmp[0]=fgetc(fp))!=EOF){
        if((ftell(fp)-http_offset)>total_len){
            sprintf(buf, "can not find %s \r\n", head_str);
            exit(0);
        }
        if(head_tmp[0]==*head_str){
            for (i = 1; i < head_len; i++)
            {
                head_tmp[i] = fgetc(fp);
                if(head_tmp[i]!=*(head_str+i))
                    break;
            }
            if(i==head_len)
            {
                ishead=1;
                break;
            }

        }
    }
    val_len = 0;
    while(ishead&&((tail_tmp[0]=fgetc(fp))!=EOF)){
        if((ftell(fp)-http_offset)>total_len){
            sprintf(buf, "can not find %s\r\n", tail_str);
            exit(0);
        }
        buf[val_len++] = tail_tmp[0];
        if(tail_tmp[0]==*tail_str){
            for (i = 1; i < tail_len;i++){
                tail_tmp[i] = fgetc(fp);
                //printf("%x  ",tail_tmp[i]);
                if(tail_tmp[i]!=*(tail_str+i))
                    break;
            }
            if(i==tail_len){
                buf[val_len - 1] = 0;
                break;
            }
        }
    }
    fseek(fp, http_offset, SEEK_SET);
}

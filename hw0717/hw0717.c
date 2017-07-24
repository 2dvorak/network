#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>

#define MACADDR_SIZE 6
#define IPADDR_SIZE 4

#define MINIMUM_HEADER_SIZE 20

#define TYPE_IPv4 0x0800
#define TYPE_IPv6 0x8d66

//#define HEADER_LENGTH(x) x*4

#define VER_4 4
#define PROTOCOL_ICMP 0x1
#define PROTOCOL_TCP 0x6
#define PROTOCOL_UDP 0X17

typedef struct my_eth_header{
	uint8_t daddr[6];
	uint8_t saddr[6];
	uint16_t type;
} eth_header;

typedef struct my_ip_header{
	uint8_t version;
	uint8_t ihl;
	uint8_t tos;
	uint16_t length;
	uint16_t id;
	uint8_t ipflag;
	uint16_t offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t saddr[4];
	uint8_t daddr[4];
	uint8_t* options;
} ip_header;

typedef struct my_tcp_header{
	uint16_t sport;
	uint16_t dport;
	uint32_t seq;
	uint32_t acknum;
	uint8_t offset;
	uint8_t reserved;
	uint8_t tcpflag;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent;
	uint8_t* options;
} tcp_header;

uint32_t header_length(uint32_t a) {
    return (uint32_t)4*a;
}

u_char* read_eth_header(u_char* packet, eth_header* eth) {
	u_char* pos = packet;
	memcpy(eth, pos, 12);
	pos += 12;
	//printf("mac addr : %x\n",eth->daddr[0]);
	eth->type = ntohs(*(int*)pos);
	pos += 2;
	//printf("eth_header->type : %x\n",eth->type);
	return pos;
}

u_char* read_ip_header(u_char* packet, ip_header* ip) {
	u_char* pos = packet;
	ip->version = (*(u_char*)pos)>>4;
	ip->ihl = (*(u_char*)pos) & 0xf;
	pos += 1;
	ip->tos = *(u_char*)pos;
	pos += 1;
	ip->length = ntohs(*(int*)pos);
	pos += 2;
	ip->id = ntohs(*(int*)pos);
	pos += 2;
	ip->ipflag = *(u_char*)pos;
	//ip += 1;
	ip->offset = ntohs((*(int*)pos))>>4;
	pos += 2;
	ip->ttl = *(u_char*)pos;
	pos += 1;
	ip->protocol = *(u_char*)pos;
	pos += 1;
	ip->checksum = ntohs(*(int*)pos);
	pos += 2;
	memcpy(ip->saddr, pos, 4);
    pos += 4;
	memcpy(ip->daddr, pos, 4);
	pos += 4;
	if(header_length(ip->length) > MINIMUM_HEADER_SIZE) {
		ip->options = (u_char*)malloc(header_length(ip->length) - MINIMUM_HEADER_SIZE);
		memcpy(ip->options, pos, header_length(ip->length) - MINIMUM_HEADER_SIZE);
	}
	pos += header_length(ip->length) - MINIMUM_HEADER_SIZE;
	//printf("ip_header->protocol : %x\n",ip->protocol);
    //printf("ip_header->version : %x\n",ip->version);
	return pos;
}

u_char* read_tcp_header(u_char* packet, tcp_header* tcp) {
	u_char* pos = (u_char*)packet;
	tcp->sport = ntohs(*(uint32_t*)pos);
	pos += 2;
	tcp->dport = ntohs(*(uint32_t*)pos);
	pos += 2;
	tcp->seq = ntohl(*(uint32_t*)pos);
	pos += 4;
	tcp->acknum = ntohl(*(uint32_t*)pos);
	pos += 4;
	tcp->offset = (*(u_char*)pos)>>4;
	//pos += 1;
	tcp->reserved = (*(u_char*)pos) & 0xf;
	pos += 1;
	tcp->tcpflag = *(u_char*)pos;
	pos += 1;
	tcp->window = ntohs(*(uint32_t*)pos);
	pos += 2;
	tcp->checksum = ntohs(*(uint32_t*)pos);
	pos += 2;
	tcp->urgent = ntohs(*(uint32_t*)pos);
	pos += 2;
	if(MINIMUM_HEADER_SIZE < header_length(tcp->offset)) {
		tcp->options = (u_char*)malloc(header_length(tcp->offset) - MINIMUM_HEADER_SIZE);
		memcpy(tcp->options, pos, header_length(tcp->offset) - MINIMUM_HEADER_SIZE);
	}
	pos += header_length(tcp->offset) - MINIMUM_HEADER_SIZE;
    //printf("tcp data content : %s\n",pos);
	return pos;
}

int32_t main(int argc, u_char *argv[])
{
	int32_t i=0, j=0, data_len;
	pcap_t *handle;			/* Session handle */
<<<<<<< HEAD
	u_char* dev = "dum0";			/* The device to sniff on */
=======
	u_char* dev = "wlan0";			/* The device to sniff on */
>>>>>>> 1b90646dddf34ee479e734eac0dd004f4b76b2ab
	u_char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	u_char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr* header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
    	time_t cap_sec = 0;   /* prevent multiple prints */
    	suseconds_t cap_usec = 0;
	/* Define the device */
	//dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

    //header = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));

    eth_header* eth;
	if(!(eth = (eth_header*)malloc(sizeof(eth_header)))) {
        free(header);
		printf("malloc for eth_header failed!\n");
		return -1;
	}
	memset(eth, 0, sizeof(eth_header));

    ip_header* ip;
    if(!(ip = (ip_header*)malloc(sizeof(ip_header)))) {
		printf("malloc for ip_header failed!\n");
        free(header);
		free(eth);
		return -1;
	}
    memset(ip, 0, sizeof(ip_header));

    tcp_header* tcp;
	if(!(tcp = (tcp_header*)malloc(sizeof(tcp_header)))) {
		printf("malloc for tcp_header failed!\n");
        free(header);
		free(eth);
		free(ip);
		return -1;
	}
	memset(tcp, 0, sizeof(tcp_header));
	/* Grab a packet */
	while(1) {
		u_char* current_pos;
		if(pcap_next_ex(handle, &header,&packet) <= 0) continue;
		current_pos = (u_char*)packet;
		/* Print its length */
		//printf("Jacked a packet with length of [%d] at %d\n", header->caplen,(int)header->ts.tv_sec);
		//sleep(1);
		if(header->caplen < 1) continue;

        	cap_sec = header->ts.tv_sec;
        	cap_usec = header->ts.tv_usec;
		//printf("packet first byte : %x\n",*(u_char*)packet);
		
		current_pos = read_eth_header(current_pos, eth);
		if(eth->type != TYPE_IPv4) continue;
		
		current_pos = read_ip_header(current_pos, ip);
        const char* dip = inet_ntop(ip->daddr);
        const char* sip = inet_ntop(ip->saddr);
		if(ip->protocol != PROTOCOL_TCP) continue;
		
		current_pos = read_tcp_header(current_pos,tcp);
		//printf("start of data : %2x\n",*(u_char*)current_pos);
        printf("Captured a packet of size [%d] at %d\n",header->caplen, (int32_t)cap_sec);
        printf("eth.smac [%02x:%02x:%02x-%02x:%02x:%02x], eth.dmac [%02x:%02x:%02x-%02x:%02x:%02x]\n",eth->saddr[0],eth->saddr[1],eth->saddr[2],eth->saddr[3],eth->saddr[4],eth->saddr[5],eth->daddr[0],eth->daddr[1],eth->daddr[2],eth->daddr[3],eth->daddr[4],eth->daddr[5]);
        //printf("ip.sip [%d.%d.%d.%d], ip.dip [%d.%d.%d.%d]\n",ip->saddr[0],ip->saddr[1],ip->saddr[2],ip->saddr[3],ip->daddr[0],ip->daddr[1],ip->daddr[2],ip->daddr[3]);
        printf("ip.sip [%s], ip.dip [%s]\n",sip, dip);
        printf("tcp.sport [%d], tcp.dport[%d]",tcp->sport, tcp->dport);
	
        data_len = ip->length - header_length(ip->ihl + tcp->offset);
        //printf("%02x",current_pos[0]);
        for(i = 0; i< data_len; i++) {
            if(i%0x10 == 0)
        		printf("\ndata 0x%04x : ",i);
		    //printf("%02x",*(u_char*)(current_pos + i));
            printf("%02x",current_pos[i]);
            if((i+1)%4 == 0) printf(" ");
            if(i%0x10 == 0xf || i == data_len - 1) {
                printf("\t");
                for(j = i - 0xf; j <= i; j++) {
                    //if((*(u_char *)current_pos + i - 0x10 + j) >= 0x20 && (*(u_char *)current_pos + i - 0x10 + j) <= 0x7e) {
                    if(current_pos[i - 0xf + j] >= 0x20 && current_pos[i - 0xf + j] <= 0x7e) {
                        printf("%c",current_pos[i - 0xf + j]);
                    } else {
                        printf(".");
                    }
                }
            }
        }
        printf("\n");
    }
	/* And close the session */
	pcap_close(handle);
    free(eth);
    free(ip);
    free(tcp);
	return(0);
}

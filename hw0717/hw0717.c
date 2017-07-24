#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
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
	//uint8_t saddr[4];
	//uint8_t daddr[4];
    struct in_addr saddr;
    struct in_addr daddr;
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

int32_t header_length(int32_t a) {
    return (int32_t)4*a;
}

u_char* read_eth_header(u_char* packet, eth_header* eth) {
	u_char* pos = packet;
	memcpy(eth, pos, 12);
	pos += 12;
	//printf("mac addr : %x\n",eth->daddr[0]);
	eth->type = ntohs(*(uint16_t*)pos);
	pos += 2;
	//printf("eth_header->type : %x\n",eth->type);
	return pos;
}

u_char* read_ip_header(u_char* packet, ip_header* ip) {
	u_char* pos = packet;
	ip->version = (*(uint8_t*)pos)>>4;
	ip->ihl = (*(uint8_t*)pos) & 0xf;
	pos += 1;
	ip->tos = *(uint8_t*)pos;
	pos += 1;
	ip->length = ntohs(*(uint16_t*)pos);
	pos += 2;
	ip->id = ntohs(*(uint16_t*)pos);
	pos += 2;
	ip->ipflag = *(uint8_t*)pos;
	//ip += 1;
	ip->offset = ntohs((*(uint16_t*)pos))>>4;
	pos += 2;
	ip->ttl = *(uint8_t*)pos;
	pos += 1;
	ip->protocol = *(uint8_t*)pos;
	pos += 1;
	ip->checksum = ntohs(*(uint16_t*)pos);
	pos += 2;
	//memcpy(ip->saddr, pos, 4);
    ip->saddr.s_addr = *(uint32_t*)pos;
    pos += 4;
	//memcpy(ip->daddr, pos, 4);
    ip->daddr.s_addr = *(uint32_t*)pos;
	pos += 4;
	if(header_length(ip->length) > MINIMUM_HEADER_SIZE) {
		ip->options = (u_char*)malloc(header_length(ip->ihl) - MINIMUM_HEADER_SIZE);
		memcpy(ip->options, pos, header_length(ip->ihl) - MINIMUM_HEADER_SIZE);
	}
    //printf("ip->length : %d\n",ip->ihl);
    //printf("IP header length : %d\n",header_length(ip->ihl));
	pos += header_length(ip->ihl) - MINIMUM_HEADER_SIZE;
	//printf("ip_header->protocol : %x\n",ip->protocol);
    //printf("ip_header->version : %x\n",ip->version);
	return pos;
}

u_char* read_tcp_header(u_char* packet, tcp_header* tcp) {
	u_char* pos = (u_char*)packet;
	tcp->sport = ntohs(*(uint16_t*)pos);
	pos += 2;
	tcp->dport = ntohs(*(uint16_t*)pos);
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
	tcp->window = ntohs(*(uint16_t*)pos);
	pos += 2;
	tcp->checksum = ntohs(*(uint16_t*)pos);
	pos += 2;
	tcp->urgent = ntohs(*(uint16_t*)pos);
	pos += 2;
	if(MINIMUM_HEADER_SIZE < header_length(tcp->offset)) {
		tcp->options = (u_char*)malloc(header_length(tcp->offset) - MINIMUM_HEADER_SIZE);
		memcpy(tcp->options, pos, header_length(tcp->offset) - MINIMUM_HEADER_SIZE);
	}
    //printf("TCP header length : %d\n",header_length(tcp->offset));
    //printf("Additional bytes in tcp header of length %d.\n",header_length(tcp->offset) - MINIMUM_HEADER_SIZE);
	pos += header_length(tcp->offset) - MINIMUM_HEADER_SIZE;
    //printf("tcp header length : %d\n",header_length(tcp->offset));
	return pos;
}

int32_t main(int32_t argc, uint8_t *argv[])
{
	int32_t i=0, j=0;
    int32_t data_len;
	pcap_t *handle;			/* Session handle */
    if(argc < 2) {
        printf("Device name not given!\n");
        printf("Usage : ./hw0717 [DEVICE]\n");
        return -1;
    }
	uint8_t* dev = argv[1];			/* The device to sniff on */
	uint8_t errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	uint8_t filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr* header;	/* The header that pcap gives us */
	const uint8_t *packet;		/* The actual packet */
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

		if(header->caplen < 1) continue;

        	cap_sec = header->ts.tv_sec;
        	cap_usec = header->ts.tv_usec;
		//printf("packet first byte : %x\n",*(u_char*)packet);
		
		current_pos = read_eth_header(current_pos, eth);
		if(eth->type != TYPE_IPv4) continue;
		
		current_pos = read_ip_header(current_pos, ip);
        char dip[INET_ADDRSTRLEN], sip[INET_ADDRSTRLEN];
        if((inet_ntop(AF_INET,&(ip->daddr),dip,INET_ADDRSTRLEN)) == NULL || (inet_ntop(AF_INET,&(ip->saddr),sip,INET_ADDRSTRLEN)) == NULL) {
            printf("Error converting ip address.\n");
            continue;
        }
		if(ip->protocol != PROTOCOL_TCP) continue;
		
		current_pos = read_tcp_header(current_pos,tcp);
		//printf("start of data : %2x\n",*(u_char*)current_pos);
        printf("Captured a packet of size [%d] at %d\n",header->caplen, (int32_t)cap_sec);
        printf("eth.smac [%02x:%02x:%02x-%02x:%02x:%02x], eth.dmac [%02x:%02x:%02x-%02x:%02x:%02x]\n",eth->saddr[0],eth->saddr[1],eth->saddr[2],eth->saddr[3],eth->saddr[4],eth->saddr[5],eth->daddr[0],eth->daddr[1],eth->daddr[2],eth->daddr[3],eth->daddr[4],eth->daddr[5]);
        //printf("ip.sip [%d.%d.%d.%d], ip.dip [%d.%d.%d.%d]\n",ip->saddr[0],ip->saddr[1],ip->saddr[2],ip->saddr[3],ip->daddr[0],ip->daddr[1],ip->daddr[2],ip->daddr[3]);
        printf("ip.sip [%s], ip.dip [%s]\n",sip, dip);
        printf("tcp.sport [%d], tcp.dport[%d]",tcp->sport, tcp->dport);
	
        data_len = ip->length - header_length(ip->ihl + tcp->offset);
        //printf("\n%02x\n",current_pos[0]);
        //continue;
        for(i = 0; i< data_len; i++) {
            if(i%0x10 == 0)
        		printf("\ndata 0x%04x : ",i);
		    //printf("%02x",*(u_char*)(current_pos + i));
            printf("%02x",current_pos[i]);
            if((i+1)%4 == 0) printf(" ");
            if(i%0x10 == 0xf) {
                printf("\t");
                for(j = i - 0xf; j <= i; j++) {
                    //if((*(u_char *)current_pos + i - 0x10 + j) >= 0x20 && (*(u_char *)current_pos + i - 0x10 + j) <= 0x7e) {
                    if(current_pos[j] >= 0x20 && current_pos[j] <= 0x7e) {
                        printf("%c",current_pos[j]);
                    } else {
                        printf(".");
                    }
                }
            }
            if(i == data_len - 1) {
                if(i%0x10 < 4) printf("\t\t\t\t\t");
                else if(i%0x10 < 8) printf("\t\t\t\t");
                else if(i%0x10 < 12) printf("\t\t\t");
                else printf("\t\t");
                for(j = (i/0x10) * 0x10; j< data_len; j++) {
                    if(current_pos[j] >= 0x20 && current_pos[j] <= 0x7e) {
                        printf("%c",current_pos[j]);
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
    free(header);
    free(eth);
    free(ip);
    free(tcp);
	return(0);
}

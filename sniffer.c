#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<net/if.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/ip.h>
#include<linux/if_ether.h>
#include<pthread.h>
#include<netinet/ip_icmp.h>   
#include<netinet/udp.h>   
#include<netinet/tcp.h>  
#include<netinet/ip.h>  
#include<unistd.h>

FILE *logs;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i=0,j;
struct sockaddr_in source,dest;
int size=0;
unsigned char buffer[65536];

int frames_number=0;
int eth2_frames=0;
int usef_len=0;
int protocol[6]={0,0,0,0,0,0};

void ProtocolIdentifier (int proto){
	switch(proto){
	
			case 1544:
				fprintf(logs,"Protocol: ARP");
				protocol[0]=protocol[0]+1;
				break;
				
			case 13696:
				fprintf(logs,"Protocol: RARP");
				protocol[1]=protocol[1]+1;
				break;
				
			case 8:
				fprintf(logs,"Protocol: IPv4");
				protocol[2]=protocol[2]+1;
				break;
				
			case 56710:
				fprintf(logs,"Protocol: IPv6");
				protocol[3]=protocol[3]+1;
				break;
			
			case 2184:
				
				fprintf(logs,"Flux Control");
				protocol[4]=protocol[4]+1;
				
				break;
			
			case 58760:
				
				fprintf(logs,"MAC Security");
				protocol[5]=protocol[5]+1;
				
				break;
				
			default: 
				fprintf(logs,"Unidentified");
				protocol[6]=protocol[6]+1;
	}
}



void PrintInHex(char *mesg, unsigned char *p, int len)
{
	fprintf(logs,"%s",mesg);
	len--;
	while(len)
	{
		fprintf(logs,"%.2X ", *p);
		p++;
		len--;
	}

}

void ParseEthernetHeader(unsigned char *packet, int len)
{
	struct ethhdr *ethernet_header;

	if(len >= 1536 /*len>=64 && len<=1500*/)
	{
		fprintf(logs,"---- Frame: %d ---- \n", frames_number);
		eth2_frames++;
		ethernet_header = (struct ethhdr *)packet;
		
		/* First set of 6 bytes are Destination MAC */
		PrintInHex("Destination MAC: ", ethernet_header->h_dest, 6);
		fprintf(logs,"\n");
		
		/* Second set of 6 bytes are Source MAC */
		PrintInHex("Source MAC: ", ethernet_header->h_source, 6);
		fprintf(logs,"\n");

		/* Last 2 bytes in the Ethernet header are the protocol it carries */
		ProtocolIdentifier(ethernet_header->h_proto);
		PrintInHex("\t Code: ",(void *)&ethernet_header->h_proto, 2);
		fprintf(logs,"\n");

		/* Calculate frame's useful load */
		usef_len = len - 18;
		fprintf(logs,"Frame length in bytes: %d\n",len);
		fprintf(logs,"Useful load in bytes: %d\n", usef_len);
		
		fprintf(logs,"\n");

	}
}

void *capturador(void *args){
    logs=fopen("sniffer.txt","a+");
    if(logs==NULL) {
	printf("Unable to create file.");
    }
    ParseEthernetHeader(buffer, size);
    frames_number++;
}

void *analizador(void *args){
	//printf("\n analizador");
	int num_pac=0;
	char nom_tar[20];
        int packet_size;
	int i=0;
	int saddr_size;
	struct sockaddr_in source_socket_address, dest_socket_address;
	struct sockaddr saddr;

	printf("Numero de paquetes a capturar: \n");
	scanf("%d",&num_pac);
	
	printf("Nombre de la tarjeta de red: \n");
	scanf("%s",nom_tar);

	int sock = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	    if(sock == -1)
	    {
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create socket");
		exit(1);
	    }

	//Modo promiscuo de tarjeta de red.
	struct ifreq ethreq;
	strncpy (ethreq.ifr_name, nom_tar, IFNAMSIZ);
	ioctl (sock,SIOCGIFFLAGS, &ethreq);
	ethreq.ifr_flags |= IFF_PROMISC;
	ioctl (sock, SIOCSIFFLAGS, &ethreq);
	
	while(i<num_pac) {
	saddr_size = sizeof saddr;
	size = recvfrom(sock , buffer , 65536, 0 , &saddr , &saddr_size);

      	if (packet_size == -1) {
        printf("Failed to get packets\n");
        //return 1;
      	}	

	pthread_t hilo2; // hilo para proceso de capturas
	pthread_create(&hilo2,NULL,capturador, NULL);
	pthread_join(hilo2,NULL);

	i=i+1;
	}
	fprintf(logs,"Ethernet 2 frames: %d\n", eth2_frames);
	fprintf(logs,"IEEE 802.3 frames: %d\n\n", frames_number-eth2_frames);
}


int main() {
	
	pthread_t hilo1; // hilo para proceso de analisis
	pthread_create(&hilo1,NULL,analizador,NULL);
	pthread_join(hilo1,NULL);
	system("/sbin/ifconfig enp0s3 -promisc");
	
	return 0;

}

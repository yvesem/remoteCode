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
#include<unistd.h>
#define MAXBUF 65536

FILE *logs;
FILE *macA;
int size = 0;
struct sockaddr_in source, dest;
unsigned char buffer[MAXBUF];
char netC[10];
int ethII = 0, frameLoad = 0, framesTotal = 0;;
int protocolNxLayer[6]={0}; // 0 -> ARP 1 -> IPV6 2 -> IPV4 3 -> CONTROL DE FLUJO 4 -> MAC Sec.
int addrType = 0; // 1 -> unidifusion 3 -> difusion 2 -> multidifusion
int isMAC = 0;

void typeOfAddr() {
	switch(addrType) {
		case 1:
			fprintf(logs," -> Direccion de unidifusion. \n");
			break;
		case 2:
			fprintf(logs," -> Direccion de multidifusion \n");
			break;
		case 3:
			fprintf(logs," -> Direccion de difusion \n");
			break;
		default:
			fprintf(logs," -> No identificado \n");
			break;
	}
}

void HextoBin(unsigned char tByt[2]) {
	unsigned char symbol;
	int j;
	int bits[4];
	for(j = 0; j < 2; j++) {
		symbol = tByt[j];
		if(symbol == '1')
			bits[3] = 1;
		if(symbol == '2')
			bits[2] = 1;
		if(symbol == '3')
		{
			bits[2] = 1;
			bits[3] = 1;
		}
		if(symbol == '4')
			bits[1] = 1;
		if(symbol == '5')
		{
			bits[1] = 1;
			bits[3] = 1;
		}
		if(symbol == '6')
		{
			bits[1]=1;
			bits[2] = 1;
		}
		if(symbol == '7'){
			bits[1] = 1;
			bits[2] = 1;
			bits[3] = 1;
		}
		if(symbol == '8')
			bits[0] = 1;
		if(symbol == '9'){
			bits[0] = 1;
			bits[3] = 1;
		}
		if(symbol == 'A') {
			bits[0] = 1;
			bits[2] = 1;
		}
		if(symbol == 'B')
		{
			bits[0] = 1;
			bits[2] = 1;
			bits[3] = 1;
		}
		if(symbol == 'C'){
			bits[0]=1;
			bits[1] = 1;
		}
		if(symbol == 'D'){
			bits[0] = 1;
			bits[1] = 1;
			bits[3] = 1;
		}
		if(symbol == 'E'){
			bits[0] = 1;
			bits[1] = 1;
			bits[2] = 1;
		}
		if(symbol == 'F') {
			bits[0] = 1;
			bits[1] = 1;
			bits[2] = 1;
			bits[3] = 1;
		}
	}
	if(bits[3] == 1) {
		addrType = 2;
	} else {
		addrType = 1;
	}
}

void ProtocolType (int typeOf){
	switch(typeOf){
			case 1544:
				fprintf(logs,"**ARP**\n");
				protocolNxLayer[0]++;
				break;
				
			case 8:
				fprintf(logs,"**IPv4**");
				protocolNxLayer[1]++;
				break;
				
			case 56710:
				fprintf(logs,"**IPv6**");
				protocolNxLayer[2]++;
				break;
			
			case 2184:
				fprintf(logs,"**Control de flujo Ethernet**");
				protocolNxLayer[3]++;
				break;
			
			case 58760:
				fprintf(logs,"**Seguridad MAC**");
				protocolNxLayer[4]++;
				break;
			default: 
				fprintf(logs,"**No identificado**");
				protocolNxLayer[5]++;
	}
}

void PrintInHex(char *mesg, unsigned char *p, int len)
{
	fprintf(logs,"%s",mesg);
	len--;
	unsigned char dif[2] = "FF";
	int i = 1;
	int j = 0;
	int h;
	while(len)
	{
		if(*p == *dif && i < 3)
		{
			addrType++; //difusion
			i = 3;
		} else
		{
			if(i < 3)
			{
				if(i==2){
					HextoBin(p);
				}
				i++;
			}
		}
		fprintf(logs,"%.2X ", *p);
		if(isMAC == 1){
			fprintf(macA,"%.2X ", *p);
		}
		p++;
		len--;
	}
}

void ParseEthernetHeader(unsigned char *packet, int len)
{
	struct ethhdr *ethernet_header;
	if(len >= 1536)
	{
		fprintf(logs,"---- Frame: %d ---- \n", framesTotal);
		ethII++;
		fprintf(logs,"Trama Ethernet II. \n");
		ethernet_header = (struct ethhdr *)packet;
		
		isMAC = 1;
		PrintInHex("MAC de destino: ", ethernet_header->h_dest, 6);
		fprintf(logs,"\n");
		fprintf(macA,"\n");
		typeOfAddr();
		
		PrintInHex("MAC de la fuente: ", ethernet_header->h_source, 6);
		fprintf(logs,"\n");
		fprintf(macA,"\n");
		typeOfAddr();
		
		isMAC = 0;
		ProtocolType(ethernet_header->h_proto);
		PrintInHex("\t Protocolo empaquetado: ",(void *)&ethernet_header->h_proto, 2);
		fprintf(logs,"\n");

		frameLoad = len - 18;
		fprintf(logs,"Tamaño (longitud) de la trama en bytes: %d\n",len);
		fprintf(logs,"Carga util en bytes: %d \n", frameLoad);
		fprintf(logs,"\n");
	}
	else {
		fprintf(logs," ---- Frame: %d ---- \n", framesTotal);
		fprintf(logs,"Trama IEEE 802.3 no puede ser analizada. \n");
	}
}

void *capturador(void *args){
    logs = fopen("sniffer.txt","a+");
    macA = fopen("direccionesMAC.txt","a+");
    if(logs==NULL) {
	printf("\n Error al abrir el archivo. ");
    }
    ParseEthernetHeader(buffer, size);
    framesTotal++;
}

void *analizador(void *args){
	int packet = 0;
	int packet_size;
	int i = 0;
	int saddr_size;
	struct sockaddr_in source_socket_address, dest_socket_address;
	struct sockaddr saddr;

	printf("Numero de paquetes a capturar: \n");
	scanf("%d",&packet);
	
	printf("Nombre de la tarjeta de red: \n");
	scanf("%s",netC);

	int s = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	 if(s == -1)
	 {
		perror("Error socket");
		exit(1);
	 }

	struct ifreq ethreq;
	strncpy (ethreq.ifr_name, netC, IFNAMSIZ);
	ioctl(s,SIOCGIFFLAGS, &ethreq);
	ethreq.ifr_flags |= IFF_PROMISC;
	ioctl(s, SIOCSIFFLAGS, &ethreq);
	
	printf("\n Analizando paquetes... \n");
	while(i<=packet) {
		saddr_size = sizeof saddr;
		size = recvfrom(s , buffer , MAXBUF, 0 , &saddr , &saddr_size);
      		if (packet_size == -1) {
        		printf("NO se pudieron procesar los paquetes. \n");
        		exit(1);
      		}	
		pthread_t captures; 
		pthread_create(&captures,NULL,capturador, NULL);
		pthread_join(captures,NULL);
		i++;
	}
	fprintf(logs,"Totales: \n");
	fprintf(logs,"Tramas Ethernet II: %d\n", ethII);
	fprintf(logs,"ARP: %d IPv4: %d IPv6: %d Control de flujo: %d Seguridad MAC: %d Otro: %d \n",protocolNxLayer[0],protocolNxLayer[1],protocolNxLayer[2],protocolNxLayer[3],protocolNxLayer[4],protocolNxLayer[5]);
	int ieeeDot = framesTotal - ethII; 
	fprintf(logs,"Tramas IEEE 802.3 (no analizadas): %d\n\n", ieeeDot);
}

int main() {
	pthread_t analize; 
	pthread_create(&analize,NULL,analizador,NULL);
	pthread_join(analize,NULL);
	char command[50];
	snprintf(command,sizeof(command),"/sbin/ifconfig %s -promisc",netC);
	system(command);
	printf("\n Analisis terminado. \n Registros en: sniffer.txt \n");
	return 0;
}

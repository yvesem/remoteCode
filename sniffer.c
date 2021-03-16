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
unsigned char buffer[MAXBUF];
char netC[10];
int ethII = 0, frameLoad = 0, framesTotal = 0, size = 0;
int protocolNxLayer[6] = {0}; // 0 -> ARP 1 -> IPV6 2 -> IPV4 3 -> CONTROL DE FLUJO 4 -> MAC Sec.
char direccionDest[18], direccionOrig[18];
uint16_t protocolo;

typedef struct _Nodo {
	char addMAC[18];
	int cantidad;
	struct _Nodo* sig;
}Nodo;

Nodo *direcc = NULL;

Nodo *memoria(char addMAC[18]) {
	Nodo *nuevo;
	nuevo = (Nodo*)malloc(sizeof(Nodo));
	nuevo->cantidad = 0;
	nuevo->cantidad++;
	strcpy(nuevo->addMAC,addMAC);
	nuevo->sig = NULL;
	return nuevo;
}

int macExists(Nodo * inicio, char addMAC[18]) {
	Nodo * aux;
	aux = inicio;
	while(aux!=NULL) {
		if(strcmp(aux->addMAC,addMAC)==0) {
			return 1;
		} else {
			aux = aux->sig;
		}
	}
	return 0;
}

Nodo *alta_inicio(Nodo *inicio, char addMAC[18]) {
	Nodo *nuevo;
	Nodo *aux;
	int isMAC;
	isMAC = macExists(inicio,addMAC);
	if(isMAC == 1) {
		aux = inicio;
		while(aux!=NULL){
			if(strcmp(aux->addMAC,addMAC) == 0) {
				aux->cantidad++;
			}
			aux = aux->sig;
		}
	} else {
		if(inicio == NULL) {
		inicio = memoria(addMAC);
		return inicio;
		} else {
			nuevo = memoria(addMAC);
			nuevo->sig = inicio;
			inicio = nuevo;
		}	
	}
	return inicio;
}

void mostrar(Nodo *inicio) {
	Nodo *aux;
	aux = inicio;
	fprintf(logs,"\n ----- MAC SUMMARY ----- \n");
	while(aux!=NULL) {
		fprintf(logs,"\n %s repetido %d veces. ", aux->addMAC, aux->cantidad);
		aux = aux->sig;
	}
	fprintf(logs,"\n ");
}

void HextoBin(char tByt[18]) {
	if(tByt[0] == 'F' && tByt[1] == 'F') {
		fprintf(logs," -> Direccion de difusion. \n");
	} else {
	   if(tByt[1] == '1' || tByt[1] == '3' || tByt[1] == '5' || tByt[1] == '7' || tByt[1] == '9' || tByt[1] == 'B' || tByt[1] == 'D' || tByt[1] == 'F') {
			fprintf(logs," -> Direccion de multidifusion. \n");
		} else {
			fprintf(logs," -> Direccion de unidifusion. \n");
		}
	}
}

void ProtocolType (int typeOf){
	switch(typeOf){
			case 1544:
				fprintf(logs,"******ARP******\n");
				protocolNxLayer[0]++;
				break;	
				
			case 8:
				fprintf(logs,"******IPv4******\n");
				protocolNxLayer[1]++;
				break;
				
			case 56710:
				fprintf(logs,"******IPv6*******\n");
				protocolNxLayer[2]++;
				break;
				
			case 2184:
				fprintf(logs,"******Control de flujo Ethernet*****\n");
				protocolNxLayer[3]++;
				break;
			
			case 58760:
				fprintf(logs,"*******Seguridad MAC******\n");
				protocolNxLayer[4]++;
				break;
			default: 
				fprintf(logs,"********No identificado********\n");
				protocolNxLayer[5]++;
				break;
	}
}

void ParseEthernetHeader(unsigned char *packet, int len)
{
	struct ethhdr *ethernet_header;
	if(len >= 1536)
	{
		fprintf(logs,"--------------- Frame: %d --------------- \n", framesTotal);
		ethII++;
		fprintf(logs,"***** Trama Ethernet II. *****");
		ethernet_header = (struct ethhdr *)packet;
		
		sprintf(direccionDest,"%02x:%02x:%02x:%02x:%02x:%02x", ethernet_header->h_dest[0],ethernet_header->h_dest[1],ethernet_header->h_dest[2], ethernet_header->h_dest[3], ethernet_header->h_dest[4], ethernet_header->h_dest[5]);
		fprintf(logs,"\n Direccion MAC destino: %s \n",direccionDest);
		HextoBin(direccionDest);
		direcc = alta_inicio(direcc,direccionDest);
		
		sprintf(direccionOrig,"%02x:%02x:%02x:%02x:%02x:%02x", ethernet_header->h_source[0],ethernet_header->h_source[1],ethernet_header->h_source[2], ethernet_header->h_source[3], ethernet_header->h_source[4], ethernet_header->h_source[5]);
		fprintf(logs,"Direccion MAC origen; %s \n",direccionOrig);
		HextoBin(direccionOrig);
		direcc = alta_inicio(direcc,direccionOrig);
		
		ProtocolType(ethernet_header->h_proto);
		protocolo = htons(ethernet_header->h_proto);
		fprintf(logs,"\nProtocolo: 0x%04X ", protocolo);
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
    if(logs==NULL) {
	printf("\n Error al abrir el archivo. ");
    }
    ParseEthernetHeader(buffer, size);
    framesTotal++;
}

void *analizador(void *args){
	int packet = 0, i = 0;
	int packet_size, saddr_size;
	struct sockaddr saddr;

	printf("Numero de paquetes a capturar: \n");
	scanf("%d",&packet);
	
	printf("Nombre de la tarjeta de red: \n");
	scanf("%s",netC);

	int s = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(s == -1)
	{
		perror("Error en socket");
		exit(1);
	}

	struct ifreq ethreq;
	strncpy (ethreq.ifr_name, netC, IFNAMSIZ);
	ioctl(s,SIOCGIFFLAGS, &ethreq);
	ethreq.ifr_flags |= IFF_PROMISC;
	ioctl(s, SIOCSIFFLAGS, &ethreq);
	
	printf("\n Analizando paquetes... \n");
	while(i<packet) {
		saddr_size = sizeof saddr;
		size = recvfrom(s, buffer, MAXBUF, 0 , &saddr , &saddr_size);
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
	mostrar(direcc);
	printf("\n Analisis terminado. \n Registros en: sniffer.txt \n");
	return 0;
}

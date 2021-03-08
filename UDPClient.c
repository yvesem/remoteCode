#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
	int s, len, num, fail, i;
	struct sockaddr_in remote_addr;
	len = sizeof(struct sockaddr);	
	memset(&remote_addr, 0,sizeof(remote_addr));
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	remote_addr.sin_port = htons(9595);
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("socket");
		return 1;
	}
	printf("\n ---- Comunicandose con el servidor---- \n");
	int end = 1;
	int wait = 0;
	while(end){
		if(wait == 0){
			printf("\n Introduzca los 4 numeros a transmitir: \n");
			for(i = 1; i < 5; i++) {
				printf("\n %d >> ",i);
				scanf(" %d",&num);
				sendto(s,&num,sizeof(num),0,(struct sockaddr *)&remote_addr,sizeof(struct sockaddr));
			}
			wait = 1;
		} else {
			printf("\n Esperando confirmacion de servidor... ");
			recvfrom(s,&fail, sizeof(fail),MSG_WAITALL,(struct sockaddr*)&remote_addr,&len);
			if(fail == 1)
			{
				printf("\n Se entregaron datos incorrectos ");
				printf("\n Preparando retransmision... ");
				wait = 0;
			} else {
				printf("\n Los datos llegaron correctamente.\n");
				end = 0;
			}
		}
	
	}
	close(s);
	return 0;
}

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

int nums[4];

void mostrar(){
	int i;
	for(i=0;i<4;i++){
		printf("\n >> %d",nums[i]);
	}
}

int solve(){
	int a, b, c;
	a = nums[0] * nums[3];
	b = a - nums[1];
	c = b * nums[2];
	return c;
}

void orden()
{
	int h,j, aux;
	for(h=0;h<4;h++){
		for(j=0;j<4;j++){
			if(nums[j] < nums[j+1]){
				aux = nums[j];
				nums[j] = nums[j+1];
				nums[j+1] = aux;
			}
		}
	}

}

int main(){
	int socketSer, buff, i, fail;
	int num, sockin_size, b, resultado, wait;
	struct sockaddr_in my_addr;
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	my_addr.sin_port = htons(9595);
	struct sockaddr_in remote_addr;
	
	socketSer = socket(AF_INET, SOCK_DGRAM,0);
	if(socketSer < 0)
	{
		perror("Error en iniciar socket");
		return 1;
	}

	b = bind(socketSer,(struct sockaddr *)&my_addr, sizeof(struct sockaddr));
	if(b < 0) {
		perror("socket");
		return 1;
	}

	int end = 1;
	wait = 0;
	printf("\n Conexion desde: %s ",inet_ntoa(remote_addr.sin_addr));
	while(end){
		if(wait == 0) {
			sockin_size = sizeof(struct sockaddr_in);
			for(i = 0; i < 4; i++) {
				recvfrom(socketSer,&num,sizeof(num),0,(struct sockaddr *)&remote_addr, &sockin_size);
				nums[i] = num;
			}
			printf("\n Numeros recibidos! ");
			mostrar();
			wait = 1;
		}
		else {
			printf("\n Procesando... \n");
			orden();
			printf("\n----Ordenado!----\n");
			mostrar();
			resultado = solve();
			if(resultado > 5000) {
				fail = 1;
				printf("\n Se recibieron datos incorrectos");
				printf("\n Resultado: %d",resultado);
				printf("\n ---- Esperando retransmision... ----");
				sendto(socketSer,&fail,sizeof(fail),MSG_CONFIRM,(struct sockaddr *)&remote_addr, sockin_size);
				wait = 0;
			}else {
				fail = 0;
				printf("\n Se recibieron datos correctos");
				printf("\n Resultado: %d \n",resultado);
				sendto(socketSer,&fail,sizeof(fail),MSG_CONFIRM,(struct sockaddr *)&remote_addr,sockin_size);
				end = 0;
			}
		}
	}
	
	close(socketSer);
	return 0;
}

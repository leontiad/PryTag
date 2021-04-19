#include <string.h>
#include <stdlib.h>
#include <gmp.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <paillier.h>
#include "openssl/sha.h"
#include <time.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>

#include "../prylib/ionet.h"
#include "../prylib/prylib.h"

#define MAXBUF 2048

static char srv_addr_a[15+1] = "127.0.0.1";
static int srv_port_a = 10001;

static int srv_port_u = 10200;

void task(mpz_t n, mpz_t r, int nuser_client, int sockfd_a, int sockfd_u){
  mpz_t aux_res, iaux_res;
  int i, j, k;
  int *clientfd_u = (int *)malloc(nuser_client*sizeof(int));
  struct sockaddr_in *client_addr_u = (struct sockaddr_in *)malloc(nuser_client*sizeof(struct sockaddr_in));;
  int *addrlen_u = (int *)malloc(nuser_client*sizeof(int));

  uint32_t tmp;
  mpz_t *aux;
  int *nusers = (int *)malloc(nuser_client*sizeof(int));;
  // Wait for user clients connections
  for (i=0; i<nuser_client; i++){
    clientfd_u[i] = accept(sockfd_u, (struct sockaddr*)&client_addr_u[i], (socklen_t *)&addrlen_u[i]);
    //    printf(" New user connection at %s:%d\n", inet_ntoa(client_addr_u[i].sin_addr), ntohs(client_addr_u[i].sin_port));
  }

  int rc;
  int tot_nusers;
  int er=1;
  do{
    tot_nusers = 0;
    printf(" Waiting for auxiliary values...\n");
    for (i=0; i<nuser_client; i++){
      recv(clientfd_u[i], &tmp, sizeof(uint32_t), 0);
      nusers[i] = ntohl(tmp);
      tot_nusers += nusers[i];
    }
    aux = (mpz_t *)malloc(tot_nusers*sizeof(mpz_t)); //users encrypted values

    k=0;
    for (i=0; i<nuser_client; i++){
      for (j=0; j<nusers[i]; j++){
	readmpz(clientfd_u[i], &(aux[k]));
	k++;
	gmp_printf  (" Round %d user %d/%d auxiliary information is %8Zd\n", er, i+1, nuser_client, aux[i]);
      }
    }

    collector(tot_nusers, &aux_res, &iaux_res, aux, n);
    gmp_printf  (" Round %d number of users %d global auxiliary information is %8Zd\n", er, tot_nusers, aux_res);

    printf("Sending Aux to aggregator...\n");
    sendmpz(sockfd_a, aux_res);
    sendmpz(sockfd_a, iaux_res);
    er++;
  } while(rc > 0);
      
  
  return;
}

int main(int argc, char** argv){
  // Arguments parsing
  int ch;
  char *cvalue = NULL;

  // Select
  fd_set readfds;

  // Network parameters
  int nuser_client;
  // A
  int sockfd_a;
  // U
  int sockfd_u, clientfd_u;
  struct sockaddr_in client_addr_u;
  int addrlen_u;

  char buffer[MAXBUF+1];
  uint32_t tmp;

  /* Parsing command line arguments */
  while ((ch = getopt(argc, argv, "A:a:c:u:l:#:h")) != -1){
    switch (ch) {
    case 'h':
      printf("Usage: %s [OPTIONS]\n", argv[0]);
      printf("  -A address                set aggregator server address        (default is 127.0.0.1)\n");
      printf("  -a port                   set aggregator server port           (default is 10000)\n");
      printf("  -u port                   set user clients server port    (default is 10001)\n");
      printf("  -h, --help                print this help and exit\n");
      printf("\n");
      return 0;
      break;
    case 'A':
      cvalue = optarg;
      sscanf(cvalue, "%s", srv_addr_a);
      printf(" Server address %s\n", srv_addr_a);
      break;
    case 'a': //Server port
      cvalue = optarg;
      sscanf(cvalue, "%d", &srv_port_a);
      printf(" Set tp server port to %d\n", srv_port_a);
      break;
    case 'u': //Server port
      cvalue = optarg;
      sscanf(cvalue, "%d", &srv_port_u);
      printf(" Set collector server port to %d\n", srv_port_u);
      break;
    }
  }
  
  /* Connecting with Aggregator */
  mpz_t n, r;
  sockfd_a = tcp_connect(srv_addr_a, srv_port_a);
  printf(" Waiting for n...\n");
  readmpz(sockfd_a, &n);
  gmp_printf(" n value is %ZX\n", n);
  printf(" Waiting for Hash...\n");
  readmpz(sockfd_a, &r);
  gmp_printf(" Hash value is %ZX\n", r);

  recv(sockfd_a, &tmp, sizeof(uint32_t), 0);
  nuser_client = ntohl(tmp);
  printf("Number of user clients is %d\n", nuser_client);


  // Listening to Collector and Users
  sockfd_u = tcp_listen(srv_port_u);

  int quit=0;
  while(!quit){
    FD_ZERO(&readfds);          /* initialize the fd set */
    FD_SET(sockfd_u, &readfds);   /* add socket fd */
    FD_SET(0, &readfds);        /* add stdin fd (0) */
    printf("Waiting for a new connection or <quit> command.\n");
    
    if (select(sockfd_u+1, &readfds, 0, 0, 0) < 0) {
      fprintf(stderr, "ERROR in select");
    }

    if (FD_ISSET(0, &readfds)) {
      fgets(buffer, MAXBUF, stdin);
      switch (buffer[0]) {
      case 'q': /* terminate the server */
	quit = 1;
	break;
      default: /* bad input */
	printf("ERROR: unknown command\n");
	printf("server> ");
	fflush(stdout);
      }
    }
    if (FD_ISSET(sockfd_u, &readfds)) {
      task(n, r, nuser_client, sockfd_a, sockfd_u);
    }
  }

  close(sockfd_a);
  close(sockfd_u);

  return 0;
}

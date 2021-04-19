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

static char srv_addr_tp[15+1] = "127.0.0.1";
static int srv_port_tp = 10000;

static int srv_port_c = 10001;
static int srv_port_u = 10100;

static int lsize=100;  //random value range
static int nuser_client=1;  //number of users client 

void task(mpz_t n, mpz_t r, int clientfd_c, int sockfd_u){
  int i, j, k;
  mpz_t *skA=malloc(sizeof(mpz_t)); //aggregator random secret key
  mpz_t *pkA=malloc(sizeof(mpz_t)); //aggregator random public key
  mpz_t aux_res;
  mpz_t iaux_res;
  mpz_t dcr_sum;

  clock_t begin, end;
  clock_t total_begin, total_end;
  double time_spent;

  uint32_t tmp;

  // Sending data the collector 
  sendmpz(clientfd_c, n);
  sendmpz(clientfd_c, r);
  tmp = htonl(nuser_client);
  send(clientfd_c, &tmp, sizeof(uint32_t), 0);

  int *clientfd_u = (int *)malloc(nuser_client*sizeof(int));
  struct sockaddr_in *client_addr_u = (struct sockaddr_in *)malloc(nuser_client*sizeof(struct sockaddr_in));;
  int *addrlen_u = (int *)malloc(nuser_client*sizeof(int));

  mpz_t *ci;
  int *nusers = (int *)malloc(nuser_client*sizeof(int));;

  // Wait for user clients connections
  for (i=0; i<nuser_client; i++){
    clientfd_u[i] = accept(sockfd_u, (struct sockaddr*)&client_addr_u[i], (socklen_t *)&addrlen_u[i]);
    //    printf(" New user connection at %s:%d\n", inet_ntoa(client_addr_u[i].sin_addr), ntohs(client_addr_u[i].sin_port));
    sendmpz(clientfd_u[i], n);
    sendmpz(clientfd_u[i], r);
  }

  int quit = 0;
  int tot_nusers;
  int er = 1;
  printf("\n");
  do{
    printf("--- Aggregation Round %d.\n", er);

    key_setup_aggregator(lsize,pkA,skA,r,n);
    tot_nusers = 0;
    printf(" Sending pkA to all users...\n");
    for (i=0; i<nuser_client; i++){
      sendmpz(clientfd_u[i], *pkA);
    }
    
    //    printf(" Waiting for encrypted values...\n");
    for (i=0; i<nuser_client; i++){
      recv(clientfd_u[i], &tmp, sizeof(uint32_t), 0);
      nusers[i] = ntohl(tmp);
      tot_nusers += nusers[i];
    }
    ci = (mpz_t *)malloc(tot_nusers*sizeof(mpz_t)); //users encrypted values

    k=0;
    for (i=0; i<nuser_client; i++){
      for (j=0; j<nusers[i]; j++){
	readmpz(clientfd_u[i], &(ci[k]));
	gmp_printf  (" Round %d user %d/%d received value is %8Zd\n\n", er, i+1, nuser_client, ci[k]);
	k++;
      }
    }
    
    readmpz(clientfd_c, &aux_res);
    readmpz(clientfd_c, &iaux_res);
    aggregate(tot_nusers, &dcr_sum,ci,aux_res,iaux_res,*skA,n);

    gmp_printf(" Round %d Sum = %8Zd\n", er, dcr_sum);

    er++;
    free(ci);
    printf("\n");
  } while(!quit);
      
  //Free memorey
  close(clientfd_c);
  //  close(clientfd_u); //TODO internally free elements

  return;
}

int main(int argc, char** argv){
  // Arguments parsing
  int ch;
  char *cvalue = NULL;

  // Select
  fd_set readfds;

  // Network parameters
  // TP
  int sockfd_tp;
  // C
  int sockfd_c, clientfd_c;
  struct sockaddr_in client_addr_c;
  int addrlen_c;
  // U
  int sockfd_u;

  char buffer[MAXBUF+1];

  /* Parsing command line arguments */
  while ((ch = getopt(argc, argv, "T:t:c:u:l:#:h")) != -1){
    switch (ch) {
    case 'h':
      printf("Usage: %s [OPTIONS]\n", argv[0]);
      printf("  -T address                set tp server address        (default is 127.0.0.1)\n");
      printf("  -t port                   set tp server port           (default is 10000)\n");
      printf("  -c port                   set collector server port    (default is 10001)\n");
      printf("  -u port                   set user  server port        (default is 10100)\n");
      printf("  -l lsize                  set size of l\n");
      printf("  -# users                  set number of user clients \n");
      printf("  -h, --help                print this help and exit\n");
      printf("\n");
      return 0;
      break;
    case 'T':
      cvalue = optarg;
      sscanf(cvalue, "%s", srv_addr_tp);
      printf(" Server address %s\n", srv_addr_tp);
      break;
    case 't': //Server port
      cvalue = optarg;
      sscanf(cvalue, "%d", &srv_port_tp);
      printf(" Set tp server port to %d\n", srv_port_tp);
      break;
    case 'c': //Server port
      cvalue = optarg;
      sscanf(cvalue, "%d", &srv_port_c);
      printf(" Set collector server port to %d\n", srv_port_c);
      break;
    case 'u': //Server port
      cvalue = optarg;
      sscanf(cvalue, "%d", &srv_port_u);
      printf(" Set user server port to %d\n", srv_port_u);
      break;
    case 'l': //L value
      cvalue = optarg;
      sscanf(cvalue, "%d", &lsize);
      printf(" Set size of l to %d\n", lsize);
      break;
    case '#': //L value
      cvalue = optarg;
      sscanf(cvalue, "%d", &nuser_client);
      printf(" Set size of user clients to %d\n", nuser_client);
      break;
    }
  }
  
  /* Initializing parameters from Trusted Party (tp) */
  mpz_t n, r;
  sockfd_tp = tcp_connect(srv_addr_tp, srv_port_tp);
  readmpz(sockfd_tp, &n); // reading n
  readmpz(sockfd_tp, &r); // reading r (hash)
  close(sockfd_tp);

  // Listening to Collector and Users
  sockfd_c = tcp_listen(srv_port_c);
  sockfd_u = tcp_listen(srv_port_u);

  int quit=0;
  while(!quit){
    FD_ZERO(&readfds);          /* initialize the fd set */
    FD_SET(sockfd_c, &readfds);   /* add socket fd */
    FD_SET(0, &readfds);        /* add stdin fd (0) */
    //    printf("Waiting for a new connection or <quit> command.\n");
    
    if (select(sockfd_c+1, &readfds, 0, 0, 0) < 0) {
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
	fflush(stdout);
      }
    }
    if (FD_ISSET(sockfd_c, &readfds)) {

	clientfd_c = accept(sockfd_c, (struct sockaddr*)&client_addr_c, (socklen_t *)&addrlen_c);
	///	printf("\n\n");
	//	printf(" New collector connection at %s:%d\n", inet_ntoa(client_addr_c.sin_addr), ntohs(client_addr_c.sin_port));
	task(n, r, clientfd_c, sockfd_u);
	//	printf(" Closing collector connection at %s:%d\n", inet_ntoa(client_addr_c.sin_addr), ntohs(client_addr_c.sin_port));
	//	printf("\n\n");

    }
  }

  close(sockfd_c);
  close(sockfd_u);

  return 0;
}

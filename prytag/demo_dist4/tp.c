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

static int srv_port = 10000;

static int nsize=2024; //size of the modulus

void task(int clientfd){
  //Key Generation
  paillier_pubkey_t* pub; //public key
  paillier_prvkey_t* prv; //private key

  mpz_t *r=malloc(sizeof(mpz_t)); //hash time

  //generate N,p,q,N^2
  paillier_keygen(nsize, &pub, &prv, paillier_get_rand_devurandom);
  gmp_printf(" Public key is %ZX (%d bits)\n", pub->n, nsize);

  //sha256(time) and store it as mpz_t ui.
  hash_time(r,pub->n);
  gmp_printf(" Hash value is %ZX\n", r);

  printf("Sending parameters...\n");
  printf(" Sending n...\n");
  sendmpz(clientfd, pub->n);
  printf(" Sending h...\n");
  sendmpz(clientfd, *r);

  close(clientfd);
  return;
}

int main(int argc, char** argv){
  // Arguments parsing
  int ch;
  char *cvalue = NULL;

  // Network parameters
  int sockfd, clientfd;
  struct sockaddr_in client_addr;
  char buffer[MAXBUF+1];
  int addrlen;

  // Select
  fd_set readfds;

  /* Parsing command line arguments */
  while ((ch = getopt(argc, argv, "p:n:h")) != -1){
    switch (ch) {
    case 'h':
      printf("Usage: %s [OPTIONS]\n", argv[0]);
      printf("  -p port                   set aggregator server port (default is 9899)\n");
      printf("  -n nsize                  set size of n\n");
      printf("  -h, --help                print this help and exit\n");
      printf("\n");
      return 0;
      break;
    case 'p': //Server port
      cvalue = optarg;
      sscanf(cvalue, "%d", &srv_port);
      printf(" Set server port to %d\n", srv_port);
      break;
    case 'n': //N value
      cvalue = optarg;
      sscanf(cvalue, "%d", &nsize);
      printf(" Set size of n to %d\n", nsize);
      break;
    }
  }
  
  /* Initializing network parameters */
  sockfd = tcp_listen(srv_port);

  addrlen=sizeof(client_addr);
  /* Accepting connections*/
  int quit=0;
  while(!quit){
    FD_ZERO(&readfds);          /* initialize the fd set */
    FD_SET(sockfd, &readfds);   /* add socket fd */
    FD_SET(0, &readfds);        /* add stdin fd (0) */
    printf("Waiting for a new connection or <quit> command.\n");
    
    if (select(sockfd+1, &readfds, 0, 0, 0) < 0) {
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
	printf("List of available commands:\n");
	printf("q - quit\n\n");
	fflush(stdout);
      }
    }
    if (FD_ISSET(sockfd, &readfds)) {
      clientfd = accept(sockfd, (struct sockaddr*)&client_addr, (socklen_t *)&addrlen);
      printf("\n");
      printf(" New connection at %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
      task(clientfd);
      printf(" Closing connection at %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
      printf("\n\n");
    }
  }

  close(sockfd);
  return 0;
}

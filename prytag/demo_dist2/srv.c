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

static int srv_port = 9898;

static int lsize=100; //random value range
static int nusers=1000; //number of users
static int nsize=2048; //size of the modulus

void task(int clientfd){
  int i;
  mpz_t *aux = (mpz_t *)malloc(nusers*sizeof(mpz_t)); //auxiliary information 
  mpz_t *pls = (mpz_t *)malloc(nusers*sizeof(mpz_t)); //users original plaintext
  mpz_t *ci  = (mpz_t *)malloc(nusers*sizeof(mpz_t)); //users encrypted values
  mpz_t *hsk = (mpz_t *)malloc(nusers*sizeof(mpz_t));

  mpz_t *skA=malloc(sizeof(mpz_t)); //aggregator random secret key 
  mpz_t *pkA=malloc(sizeof(mpz_t)); //aggregator random public key 
  mpz_t *r=malloc(sizeof(mpz_t)); //hash time
  mpz_t *aux_res=malloc(sizeof(mpz_t)); //collector result
  mpz_t *iaux_res=malloc(sizeof(mpz_t)); //inverse of the collector result
  mpz_t *dcr_sum=malloc(sizeof(mpz_t)); 
  mpz_t *pls_sum=malloc(sizeof(mpz_t)); 

  clock_t begin, end;
  clock_t total_begin, total_end;
  double time_spent;

  /* Setup */
    
  //Key Generation
  paillier_pubkey_t* pub; //public key
  paillier_prvkey_t* prv; //private key

  printf("Simulation parameters\n");
  printf(" Number of users     = %8d \n", nusers);
  printf(" Random number range = %8d \n", lsize);

  //generate N,p,q,N^2
  paillier_keygen(nsize, &pub, &prv, paillier_get_rand_devurandom);
  gmp_printf(" Public key is %ZX (%d bits)\n", pub->n, nsize);
    
  //sha256(time) and store it as mpz_t ui.
  hash_time(r,pub->n);
  gmp_printf(" Hash value is %ZX\n", r);

  printf("Sending parameters...\n");
  uint32_t net_nusers = htonl(nusers);
  uint32_t net_lsize = htonl(lsize);
  send(clientfd, &net_nusers, sizeof(uint32_t), 0);
  send(clientfd, &net_lsize, sizeof(uint32_t), 0);
  
  printf(" Sending n...\n");
  sendmpz(clientfd, pub->n);

  printf(" Sending h...\n");
  sendmpz(clientfd, *r);

  int rc;

  do{
    key_setup_aggregator(lsize,pkA,skA,*r,pub->n);

    printf(" Sending pkA...\n");
    sendmpz(clientfd, *pkA);

    printf("Waiting for c and aux vector...\n");

    mpz_init(*pls_sum);
    mpz_set_ui(*pls_sum,0);
    for (i=0;i<nusers;i++){
      rc = readmpz(clientfd,&pls[i]);
      rc = readmpz(clientfd,&ci[i]);
      rc = readmpz(clientfd,&aux[i]);
      mpz_add(*pls_sum,*pls_sum,pls[i]);
    }

    /* Collect */
    collector(nusers, aux_res,iaux_res,aux,pub->n);

    /* Aggregate  */
    begin = clock();
    aggregate(nusers, dcr_sum,ci,*aux_res,*iaux_res,*skA,pub->n);
    end=clock();
    time_spent += (double)(end - begin) / CLOCKS_PER_SEC;
    printf  (" Aggregation time   = %15f\n",time_spent);
  
    gmp_printf(" Plaintext sum           = %8Zd\n", *pls_sum);

    if(mpz_cmp(*pls_sum, *dcr_sum)==0){
      printf(" +OK - decrypted sum is correct\n");
    }
    printf("\n");
  }  while(rc > 0);

  printf("Exit.\n");

  //Free memorey
  for(i=0;i<nusers;i++){
    mpz_clear(aux[i]);
    mpz_clear(pls[i]);
    mpz_clear(ci[i]);
  }
  free(aux);
  free(pls);
  free(ci);
  free(skA);
  free(pkA);
  free(r);
  free(aux_res);
  free(iaux_res);
  free(pls_sum);
  free(dcr_sum);
  
  shutdown(clientfd, SHUT_RDWR);
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

  //  signal(SIGPIPE, SIG_IGN);

  /* Parsing command line arguments */
  while ((ch = getopt(argc, argv, "hv:p:u:n:l:")) != -1){
    switch (ch) {
    case 'h':
      printf("Usage: %s [OPTIONS]\n", argv[0]);
      printf("  -p port                   set server port (default is 9898)\n");
      printf("  -u nusers                 set number of users\n");
      printf("  -n nsize                  set size of n\n");
      printf("  -l lsize                  set size of l\n");
      printf("  -h, --help                print this help and exit\n");
      printf("\n");
      return 0;
      break;
    case 'p': //Server port
      cvalue = optarg;
      sscanf(cvalue, "%d", &srv_port);
      printf(" Set server port to %d\n", srv_port);
      break;
    case 'u': //Users
      cvalue = optarg;
      sscanf(cvalue, "%d", &nusers);
      printf(" Set number of users to %d\n", nusers);
      break;
    case 'n': //N value
      cvalue = optarg;
      sscanf(cvalue, "%d", &nsize);
      printf(" Set size of n to %d\n", nsize);
      break;
    case 'l': //L value
      cvalue = optarg;
      sscanf(cvalue, "%d", &lsize);
      printf(" Set size of l to %d\n", lsize);
      break;
    }
  }
  
  /* Initializing network parameters */
  sockfd = tcp_listen(srv_port);

  addrlen=sizeof(client_addr);
  /* Accepting connections*/
  while(1){
    clientfd = accept(sockfd, (struct sockaddr*)&client_addr, (socklen_t *)&addrlen);
    printf(" New connection at %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    task(clientfd);
    printf(" Closing connection at %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    printf("\n\n");
  }

  shutdown(sockfd, SHUT_RDWR);
  close(sockfd);

  return 0;
}

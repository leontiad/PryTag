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

static int lsize=100; //random value range
static int nusers=1000; //number of users
static int nsize=2048; //size of the modulus

static char srv_addr[15+1] = "127.0.0.1";
static int srv_port = 9898;

int main(int argc, char** argv){
  // Arguments parsing
  int ch;
  char *cvalue = NULL;

  int sockfd;
  struct sockaddr_in dest;
  int addrlen;

  int i;
  uint32_t net_nusers, net_lsize;
  mpz_t n, pkA, r;
  mpz_t *hsk,*sk;
  mpz_t *pls, *ci;
  mpz_t *aux;

  clock_t begin, end;
  double time_spent;

  /* parsing command line arguments */
  while ((ch = getopt(argc, argv, "hv:a:p:")) != -1){
    switch (ch) {
    case 'h':
      printf("Usage: %s [OPTIONS]\n", argv[0]);
      printf("  -a address                set server address (default is 127.0.0.1)\n");
      printf("  -p port                   set server port (default is 9898)\n");
      printf("  -h, --help                print this help and exit\n");
      printf("\n");
      return 0;
      break;
    case 'a':
      cvalue = optarg;
      sscanf(cvalue, "%s", srv_addr);
      printf(" Server address %s\n", srv_addr);
      break;
    case 'p':
      cvalue = optarg;
      sscanf(cvalue, "%d", &srv_port);
      printf(" Server port %d\n", srv_port);
      break;
    }
  }
  printf("#Client starts.\n");
  
  /* Initializing network parameters */
  sockfd = tcp_connect(srv_addr, srv_port);

  /* Gathering parameters from the servers */
  
  mpz_init(n);
  mpz_init(pkA);
  mpz_init(r);

  printf(" Waiting for parameters...\n");
  recv(sockfd, &net_nusers, sizeof(uint32_t), 0);
  nusers = ntohl(net_nusers);
  recv(sockfd, &net_lsize, sizeof(uint32_t), 0);
  lsize = ntohl(net_lsize);
  printf("Simulation parameters received correctly.\n");
  printf(" Number of users     = %8d \n", nusers);
  printf(" Random number range = %8d \n", lsize);

  printf(" Waiting for n...\n");
  readmpz(sockfd, &n);
  gmp_printf(" n value is %ZX\n", n);

  printf(" Waiting for Hash...\n");
  readmpz(sockfd, &r);
  gmp_printf(" Hash value is %ZX\n", r);

  hsk = (mpz_t *)malloc(nusers*sizeof(mpz_t));
  sk = (mpz_t *)malloc(nusers*sizeof(mpz_t));
  aux = (mpz_t *)malloc(nusers*sizeof(mpz_t));

  while(1){
    getc(stdin);
    
    printf("New encryption round.\n");

    printf(" Waiting for pkA...\n");
    readmpz(sockfd, &pkA);
    gmp_printf(" pkA value is %ZX\n", pkA);

    key_setup_users(nusers,lsize,hsk,sk,r,n);

    aux_info(nusers,aux,sk,pkA,n);

    /* Encrypt */
    gmp_randstate_t rand;

    pls = (mpz_t *)malloc(nusers*sizeof(mpz_t)); //users original plaintext
    ci  = (mpz_t *)malloc(nusers*sizeof(mpz_t)); //users encrypted values
    for (i=0;i<nusers;i++){
      begin = clock();
      mpz_init(pls[i]);
      init_rand(rand, paillier_get_rand_devurandom, 128);
      //Generate a uniformly distributed random integer in the range 0 to 2^n−1, inclusive.
      mpz_urandomb(pls[i],rand,8);
      //    mpz_init_set_ui(pls[i],(unsigned long int)i+1); //assigning user i value i+1
      user_encrypt(&ci[i],pls[i],hsk[i],n);
      gmp_printf(" Encrypting value %Zd into %ZX\n", pls[i], ci[i]);
      end=clock();
      time_spent += (double)(end - begin) / CLOCKS_PER_SEC;
    }
    time_spent = time_spent / nusers;
    printf  (" Avg   Encrypting time   = %15f\n",time_spent);

    // Send results
    printf("Sending c and aux vector...\n");
    for (i=0;i<nusers;i++){
      sendmpz(sockfd,pls[i]);
      sendmpz(sockfd,ci[i]);
      sendmpz(sockfd,aux[i]);
    }
    printf("\n");
  }
  
  close(sockfd);
  
  return 0;
}

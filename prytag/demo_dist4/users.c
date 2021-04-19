#include <string.h>
#include <stdlib.h>
#include <gmp.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <paillier.h>
#include "openssl/sha.h"
#include <time.h>

#include <ctype.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>

#include "../prylib/ionet.h"
#include "../prylib/prylib.h"

#define MAXBUF 2048

static int lsize=100; //random value range
static int nusers=1; //number of users

static char srv_addr_a[15+1] = "127.0.0.1";
static int srv_port_a = 10100;

static char srv_addr_c[15+1] = "127.0.0.1";
static int srv_port_c = 10200;

int main(int argc, char** argv){
  // Arguments parsing
  int ch;
  char *cvalue = NULL;

  int sockfd_c;
  int sockfd_a;

  int i;
  uint32_t net_nusers, net_lsize;
  mpz_t n, pkA, r;
  mpz_t *hsk,*sk;
  mpz_t *pls, *ci;
  mpz_t *aux;

  char buffer[MAXBUF+1];

  clock_t begin, end;
  double time_spent;

  uint32_t tmp;

  /* parsing command line arguments */
  while ((ch = getopt(argc, argv, "A:a:C:c:h")) != -1){
    switch (ch) {
    case 'h':
      printf("Usage: %s [OPTIONS]\n", argv[0]);
      printf("  -A address                set aggregator server address (default is 127.0.0.1)\n");
      printf("  -a port                   set aggregator server port (default is 9898)\n");
      printf("  -C address                set collector server address (default is 127.0.0.1)\n");
      printf("  -c port                   set collector server port (default is 9898)\n");
      printf("  -h, --help                print this help and exit\n");
      printf("\n");
      return 0;
      break;
    case 'A':
      cvalue = optarg;
      sscanf(cvalue, "%s", srv_addr_a);
      printf(" Server address %s\n", srv_addr_a);
      break;
    case 'a':
      cvalue = optarg;
      sscanf(cvalue, "%d", &srv_port_a);
      printf(" Server port %d\n", srv_port_a);
      break;
    case 'C':
      cvalue = optarg;
      sscanf(cvalue, "%s", srv_addr_c);
      printf(" Server address %s\n", srv_addr_c);
      break;
    case 'c':
      cvalue = optarg;
      sscanf(cvalue, "%d", &srv_port_c);
      printf(" Server port %d\n", srv_port_c);
      break;
    case 'l': //L value
      cvalue = optarg;
      sscanf(cvalue, "%d", &lsize);
      printf(" Set size of l to %d\n", lsize);
      break;
    case 'n': //nusers value
      cvalue = optarg;
      sscanf(cvalue, "%d", &nusers);
      printf(" Set size of l to %d\n", nusers);
      break;
    }
  }
  printf("#Client starts.\n");
  
  /* Initializing network parameters */
  sockfd_c = tcp_connect(srv_addr_c, srv_port_c);
  sockfd_a = tcp_connect(srv_addr_a, srv_port_a);

  /* Gathering parameters from the servers */
  
  mpz_init(n);
  mpz_init(r);
  mpz_init(pkA);

  printf(" Waiting for n...\n");
  readmpz(sockfd_a, &n);
  gmp_printf(" n value is %ZX\n", n);

  printf(" Waiting for Hash...\n");
  readmpz(sockfd_a, &r);
  gmp_printf(" Hash value is %ZX\n", r);

  int er = 1;

  while(1){
    printf(" --- Encryption round %d.\n", er);
    //    printf(" > Select number of users (default %d):\n", nusers);
    fgets(buffer, MAXBUF, stdin);
    if(isdigit(buffer[0]))
      sscanf(buffer, "%d", &nusers);

    hsk = (mpz_t *)malloc(nusers*sizeof(mpz_t));
    sk = (mpz_t *)malloc(nusers*sizeof(mpz_t));
    aux = (mpz_t *)malloc(nusers*sizeof(mpz_t));
  
    printf(" Waiting for pkA...\n");
    readmpz(sockfd_a, &pkA);
    gmp_printf(" pkA value is %ZX\n\n", pkA);

    key_setup_users(nusers,lsize,hsk,sk,r,n);
    aux_info(nusers,aux,sk,pkA,n);

    /* Encrypt */
    gmp_randstate_t rand;

    pls = (mpz_t *)malloc(nusers*sizeof(mpz_t)); //users original plaintext
    ci  = (mpz_t *)malloc(nusers*sizeof(mpz_t)); //users encrypted values
    mpz_t sum;
    mpz_init(sum);
    for (i=0;i<nusers;i++){
      mpz_init(pls[i]);
      init_rand(rand, paillier_get_rand_devurandom, 128);
      //Generate a uniformly distributed random integer in the range 0 to 2^n−1, inclusive.
      mpz_urandomb(pls[i],rand,8);
      mpz_add(sum,sum,pls[i]);
      user_encrypt(&ci[i],pls[i],hsk[i],n);
      gmp_printf  ("Round %d measured value %8Zd encrypted into %8ZX\n", er++, pls[i], ci[i]);
    }

    // Send results
    printf("Sending encrypted values to Aggregator...\n");
    printf("Sending auxiliary informations to Collector...\n");
    tmp = htonl(nusers);
    send(sockfd_a, &tmp, sizeof(uint32_t), 0);
    send(sockfd_c, &tmp, sizeof(uint32_t), 0);
    for (i=0;i<nusers;i++){
      sendmpz(sockfd_a,ci[i]);
      sendmpz(sockfd_c,aux[i]);
    }

    printf("\n");
  }
  
  close(sockfd_c);
  close(sockfd_a);
  
  return 0;
}

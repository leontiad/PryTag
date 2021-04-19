#include <string.h>
#include <stdlib.h>
#include <gmp.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <paillier.h>
#include "openssl/sha.h"
#include <time.h>

#include "../prylib/prylib.h"

static int lsize=100; //random value range
static int nusers=10; //number of users
static int nsize=2024; //size of the modulus

static int verbose=0; //bool for verbosity

void test(){
  int i;
  mpz_t *aux = (mpz_t *)malloc(nusers*sizeof(mpz_t)); //auxiliary information 
  mpz_t *pls = (mpz_t *)malloc(nusers*sizeof(mpz_t)); //users original plaintext
  mpz_t *ci  = (mpz_t *)malloc(nusers*sizeof(mpz_t)); //users encrypted values
  mpz_t *hsk = (mpz_t *)malloc(nusers*sizeof(mpz_t));
  mpz_t *sk = (mpz_t *)malloc(nusers*sizeof(mpz_t));

  mpz_t *skA=malloc(sizeof(mpz_t)); //aggregator random secret key 
  mpz_t *pkA=malloc(sizeof(mpz_t)); //aggregator random public key 
  mpz_t *r=malloc(sizeof(mpz_t)); //hash time
  mpz_t *aux_res=malloc(sizeof(mpz_t)); //collector result
  mpz_t *iaux_res=malloc(sizeof(mpz_t)); //inverse of the collector result
  mpz_t *sum=malloc(sizeof(mpz_t)); 

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

  //generate secret keys for the users and the aggregator
  //  key_setup(hsk,pkA,skA,*r,pub);
  key_setup_aggregator(lsize,pkA,skA,*r,pub->n);
  key_setup_users(nusers,lsize,hsk,sk,*r,pub->n);

  //generate aux for each user H(t)^skAski and store it in aux[]
  //  aux_info(aux,hsk,*skA,pub);
  begin = clock();

  aux_info(nusers,aux,sk,*pkA,pub->n);

  end = clock();
  time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  time_spent = time_spent / nusers;
  printf("%f\n", time_spent);

  /* Encrypt */
  begin = clock();

  for (i=0;i<nusers;i++){
    //    mpz_init(ci[i]);
    mpz_init(pls[i]);
    mpz_init_set_ui(pls[i],(unsigned long int)i+1); //assigning user i value i+1
    user_encrypt(&ci[i],pls[i],hsk[i],pub->n);
  }

  end=clock();
  time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  time_spent = time_spent / nusers;
  printf("%f\n", time_spent);

  /* Collect */
  begin = clock();

  collector(nusers,aux_res,iaux_res,aux,pub->n);

  end=clock();
  time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  time_spent = time_spent;
  printf("%f\n", time_spent);

  /* Aggregate  */
  begin = clock();

  aggregate(nusers,sum,ci,*aux_res,*iaux_res,*skA,pub->n);

  end=clock();
  time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  time_spent = time_spent;
  printf("%f\n", time_spent);

  gmp_printf(" SUM value %Zd \n", sum);

  //Free memorey
  for(i=0;i<nusers;i++){
    mpz_clear(aux[i]);
    mpz_clear(pls[i]);
    mpz_clear(ci[i]);
    mpz_clear(sk[i]);
  }
  free(aux);
  free(pls);
  free(ci);
  free(sk);
  free(skA);
  free(pkA);
  free(r);
  free(aux_res);
  free(iaux_res);
  free(sum);
  return;
}

int main(int argc, char** argv){
  int ch;
  char *cvalue = NULL;

  printf("#Starting simulation.\n");
  while ((ch = getopt(argc, argv, "vu:n:l:")) != -1){
    switch (ch) {
    case 'v':
      verbose = 1;
      break;
    case 'u':
      cvalue = optarg;
      sscanf(cvalue, "%d", &nusers);
      printf(" Set number of users to %d\n", nusers);
      break;
    case 'n':
      cvalue = optarg;
      sscanf(cvalue, "%d", &nsize);
      printf(" Set size of n to %d\n", nsize);
      break;
    case 'l':
      cvalue = optarg;
      sscanf(cvalue, "%d", &lsize);
      printf(" Set size of l to %d\n", lsize);
      break;
    }
  }
  test();
  printf("#End simulation.\n");
  return 0;
}    

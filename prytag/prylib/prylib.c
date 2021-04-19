#include <string.h>
#include <stdlib.h>
#include <gmp.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <paillier.h>
#include "openssl/sha.h"
#include <time.h>

#include "prylib.h"

void aggregate(int nusers, mpz_t *res,mpz_t ci[],mpz_t auxt,mpz_t iauxt,mpz_t skA,mpz_t n){
  mpz_t *pt=malloc(sizeof(mpz_t));
  clock_t begin, end;
  double time_spent;
  mpz_t n_squared;

  mpz_init(n_squared);
  mpz_mul(n_squared, n, n);

  mpz_init(*res);

  begin=clock();

  //Calculating pt
  multiply_array(nusers,pt,ci,n);
  mpz_powm(*pt,*pt,skA,n_squared);

  //Calculating It
  mpz_mul(*res,*pt,iauxt);
  mpz_mod(*res,*res,n_squared);
  mpz_sub_ui(*res,*res,1);

  //Calculating Pom1 in res
  mpz_div(*res,*res,n);
    
  //Calculating Pom2 in iskA
  mpz_t iskA;
  mpz_init(iskA);
  mpz_mod(skA, skA, n);
  mpz_invert(iskA, skA, n);

  mpz_mul(*res,*res,iskA);
  mpz_mod(*res,*res,n);

  end = clock();
  time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

  //Free memory
  mpz_clear(iskA);
  mpz_clear(*pt);
  free(pt);

  return;
}

/*
 * Fill the auxiliary information for each user
 * aux_{i,t} = (pk_{A,t})^{ski} = H(t)^{skA*ski}
 */
void aux_info(int nusers, mpz_t aux[],mpz_t sk[],mpz_t pkA,mpz_t n){
  clock_t begin, end;
  clock_t total_begin, total_end;

  mpz_t n_squared;

  mpz_init(n_squared);
  mpz_mul(n_squared, n, n);
  
  int i;
  for (i=0;i<nusers;i++){
    mpz_init(aux[i]);
    mpz_powm(aux[i],pkA,sk[i],n_squared);
    //    gmp_printf  ("Auxiliary information %8Zd\n", aux[i]);
  }
  return;
}

void collector(int nusers, mpz_t *res,mpz_t *ires,mpz_t aux[],mpz_t n){
  mpz_t n_squared;

  mpz_init(n_squared);
  mpz_mul(n_squared, n, n);

  multiply_array(nusers,res,aux,n);
  mpz_init(*ires);
  mpz_invert(*ires, *res, n_squared);
  return;
}

/*
 * Hashing the time
 */
char *get_time(){
  time_t rawtime;
  struct tm * timeinfo;
  time ( &rawtime );
  timeinfo = localtime ( &rawtime );
  return asctime(timeinfo);
}

void sha256(char *string, char outputBuffer[65]){
  // printf(" String to hash = %s",string);
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, string, strlen(string));
  SHA256_Final(hash, &sha256);
  int i = 0;
  for(i = 0; i < SHA256_DIGEST_LENGTH; i++){
    sprintf(outputBuffer + (i * 2), "%02X", hash[i]);
  }
  outputBuffer[64] = 0;
}

unsigned long int sha256_to_ui(){
  mpz_t *res;
  static unsigned char buffer[64];

  sha256(get_time(), (char *)buffer);
  // printf(" %s\n",buffer);
  //convert byte array to uunsigned long int
  unsigned long int number = *((unsigned long int*)buffer);

  return number;
}

void hash_time(mpz_t *res,mpz_t n){
  mpz_t r;
  mpz_t n_squared;

  mpz_init(n_squared);
  mpz_mul(n_squared, n, n);
  mpz_init_set_ui(*res,sha256_to_ui());

  mpz_init(r);
  do{
    mpz_add_ui(*res,*res,1);
    mpz_gcd(r,n_squared,*res);
  }
  while(mpz_cmp_ui(r,1)!=0 || mpz_cmp(*res,n_squared)>=0);

  return;
}

void multiply_array(int nusers, mpz_t *res,mpz_t array[],mpz_t n){
  int i;
  mpz_t n_squared;

  mpz_init(n_squared);
  mpz_mul(n_squared, n, n);

  mpz_init_set_ui(*res,(unsigned long int)1);
  for (i=0;i<nusers;i++){
    mpz_mul(*res,*res,array[i]);
    mpz_mod(*res,*res,n_squared);
  }
}

/*
 * Encrypt user data 
 * ci = (1+xi*N)*H^{ski}
 */
void user_encrypt(mpz_t *res,mpz_t x,mpz_t hsk,mpz_t n){
  clock_t begin, end;
  mpz_t n_squared;
  mpz_init(*res);
  mpz_init(n_squared);

  mpz_mul(n_squared, n, n);

  mpz_mul(*res, x, n); // xi*N
  mpz_add_ui(*res,*res,(unsigned long int)1); // 1+xi*N
  mpz_mod(*res, *res, n_squared);
    
  mpz_mul(*res, *res, hsk); // (xi*N)*aux == (xi*N)*(H(t)^{ski})
  mpz_mod(*res, *res, n_squared);

  return;
}

void key_setup_aggregator(int lsize, mpz_t *pkA, mpz_t *skA,mpz_t hashtime,mpz_t n){
  int i;
  gmp_randstate_t rand;
  mpz_t r, n_squared;
    
  mpz_init(r);  
  mpz_init(n_squared);

  mpz_mul(n_squared, n, n);

  init_rand(rand, paillier_get_rand_devurandom, 128);

  /* Generate a key for the aggregator */
  mpz_init(*skA);
  mpz_init(*pkA);
  do{
    mpz_urandomb(*skA,rand,lsize);
    mpz_gcd(r,n_squared,*skA);
  } while(mpz_cmp(*skA,n)>1 &&
	  mpz_cmp_ui(r,1)!=0); //checking skA belongs group Z_{n2}
  //mpz_mod(*skA, *skA, pub->n_squared);

  // gmp_printf (" skA = %ZX\n", *skA);

  mpz_powm(*pkA, hashtime, *skA, n_squared);
  
  // gmp_printf (" pkA = %ZX\n", *pkA);

  return;
}

/*
 * Setting up the private key for the users <sk[]> and the aggregator <skA>
 * the public key for the aggregator pk_{A,t} = H^{skA} 
 */
void key_setup_users(int nusers, int lsize, mpz_t hsk[],mpz_t sk[],mpz_t hashtime,mpz_t n){
  int i;
  gmp_randstate_t rand;
  mpz_t r, n_squared;
  //  mpz_t *sk = (mpz_t *)malloc(nusers*sizeof(mpz_t));

  mpz_init(r);
  mpz_init(n_squared);

  mpz_mul(n_squared, n, n);

  //  printf(" Key setup\n");

  /* Generate a key for each user */
  for (i=0;i<nusers;i++){
    init_rand(rand, paillier_get_rand_devurandom, 128);
    mpz_init(sk[i]);
    mpz_init(hsk[i]);
    do{
      mpz_urandomb(sk[i],rand,lsize);
    }while(mpz_cmp_ui(sk[i],0)==0);
    // gmp_printf (" sk%d = %ZX\n",i, sk[i]);
    mpz_powm(hsk[i],hashtime,sk[i],n_squared);
    //  gmp_printf (" hsk%d= %ZX\n",i, hsk[i]);
  }

  return;
}

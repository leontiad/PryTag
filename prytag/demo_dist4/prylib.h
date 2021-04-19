#ifndef __PRYLIB_h__
#define __PRYLIB_h__

// Expose functions from paillier library
void init_rand( gmp_randstate_t rand, paillier_get_rand_t get_rand, int bytes );

void aggregate(int nusers, mpz_t *res,mpz_t ci[],mpz_t auxt,mpz_t iauxt,mpz_t skA,mpz_t n);
void aux_info(int nusers, mpz_t aux[],mpz_t sk[],mpz_t pkA,mpz_t n);
void collector(int nusers, mpz_t *res,mpz_t *ires,mpz_t aux[],mpz_t n);
void key_setup_aggregator(int lsize, mpz_t *pkA, mpz_t *skA,mpz_t hashtime,mpz_t n);
void key_setup_users(int nusers, int lsize, mpz_t hsk[],mpz_t sk[],mpz_t hashtime,mpz_t n);
void hash_time(mpz_t *res,mpz_t n);
void multiply_array(int nusers, mpz_t *res,mpz_t array[],mpz_t n);
void user_encrypt(mpz_t *res,mpz_t x,mpz_t hsk,mpz_t n);

#endif

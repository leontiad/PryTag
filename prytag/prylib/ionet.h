#ifndef __IONET_h__
#define __IONET_h__

#include "ionet.h"
#include <gmp.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MAXLINE 2048
#define MAXBUF 2048

int tcp_connect(const char *srv_addr, int srv_port);
int tcp_listen(int srv_port);

ssize_t	readn(int fd, void *vptr, size_t n);
ssize_t Readn(int fd, void *ptr, size_t nbytes);
ssize_t readline(int fd, void *ptr, size_t maxlen);
ssize_t Readline(int fd, void *ptr, size_t maxlen);

void sendmpz(int fd, mpz_t x);
ssize_t readmpz(int fd, mpz_t *x);

#endif

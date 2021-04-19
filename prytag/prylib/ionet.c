/* include readn */

#include <sys/socket.h>
#include <sys/types.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include	"ionet.h"

static int	read_cnt;
static char	*read_ptr;
static char	read_buf[MAXLINE];


int
tcp_connect(const char *srv_addr, int srv_port)
{
  int sockfd;
  struct sockaddr_in dest;

  if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ){
    perror("Socket");
    exit(errno);
  }

  bzero(&dest, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(srv_port);

  if ( inet_aton(srv_addr, (struct in_addr *)&dest.sin_addr.s_addr) == 0 ){
    perror(srv_addr);
    exit(errno);
  }

  if ( connect(sockfd, (struct sockaddr*)&dest, sizeof(dest)) != 0 ){
    perror("Connect ");
    exit(errno);
  }
  return(sockfd);
}

int tcp_listen(int srv_port){
  int sockfd;
  struct sockaddr_in self;

  if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ){
    perror("Socket");
    exit(errno);
  }

  bzero(&self, sizeof(self));
  self.sin_family = AF_INET;
  self.sin_port = htons(srv_port);
  self.sin_addr.s_addr = INADDR_ANY;

  if ( bind(sockfd, (struct sockaddr*)&self, sizeof(self)) != 0 ){
    perror("socket--bind");
    exit(errno);
  }

  if ( listen(sockfd, 20) != 0 ){
    perror("socket--listen");
    exit(errno);
  }
  return(sockfd);
}

static ssize_t
my_read(int fd, char *ptr)
{

  if (read_cnt <= 0) {
  again:
    if ( (read_cnt = read(fd, read_buf, sizeof(read_buf))) < 0) {
      if (errno == EINTR)
	goto again;
      return(-1);
    } else if (read_cnt == 0)
      return(0);
    read_ptr = read_buf;
  }

  read_cnt--;
  *ptr = *read_ptr++;
  return(1);
}

ssize_t
readline(int fd, void *vptr, size_t maxlen)
{
  ssize_t	n, rc;
  char	c, *ptr;

  ptr = vptr;
  for (n = 1; n < maxlen; n++) {
    if ( (rc = my_read(fd, &c)) == 1) {
      *ptr++ = c;
      if (c == '\n')
	break;	/* newline is stored, like fgets() */
    } else if (rc == 0) {
      *ptr = 0;
      return(n - 1);	/* EOF, n - 1 bytes were read */
    } else
      return(-1);		/* error, errno set by read() */
  }

  *ptr = 0;	/* null terminate like fgets() */
  return(n);
}

ssize_t
readlinebuf(void **vptrptr)
{
  if (read_cnt)
    *vptrptr = read_ptr;
  return(read_cnt);
}
/* end readline */

ssize_t
Readline(int fd, void *ptr, size_t maxlen)
{
  ssize_t		n;

  if ( (n = readline(fd, ptr, maxlen)) < 0)
    perror("readline error");
  return(n);
}

ssize_t						/* Read "n" bytes from a descriptor. */
readn(int fd, void *vptr, size_t n)
{
  size_t	nleft;
  ssize_t	nread;
  char	*ptr;

  ptr = vptr;
  nleft = n;
  while (nleft > 0) {
    if ( (nread = read(fd, ptr, nleft)) < 0) {
      if (errno == EINTR)
	nread = 0;		/* and call read() again */
      else
	return(-1);
    } else if (nread == 0)
      break;				/* EOF */

    nleft -= nread;
    ptr   += nread;
  }
  return(n - nleft);		/* return >= 0 */
}
/* end readn */

ssize_t
Readn(int fd, void *ptr, size_t nbytes)
{
  ssize_t		n;

  if ( (n = readn(fd, ptr, nbytes)) < 0)
    perror("readn error");
  return(n);
}
ssize_t						/* Write "n" bytes to a descriptor. */
writen(int fd, const void *vptr, size_t n)
{
  size_t		nleft;
  ssize_t		nwritten;
  const char	*ptr;

  ptr = vptr;
  nleft = n;
  while (nleft > 0) {
    if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
      if (nwritten < 0 && errno == EINTR)
	nwritten = 0;		/* and call write() again */
      else
	return(-1);			/* error */
    }

    nleft -= nwritten;
    ptr   += nwritten;
  }
  return(n);
}
void
Writen(int fd, void *ptr, size_t nbytes)
{
  if (writen(fd, ptr, nbytes) != nbytes)
    perror("writen error");
}
void
sendmpz(int fd, mpz_t x)
{
  static char buffer[MAXBUF+1];
  size_t buffer_size;

  bzero(buffer, sizeof(buffer));
  mpz_export(buffer, &buffer_size, 1, sizeof(buffer[0]), 0, 0, x);
  uint32_t tmp = htonl(buffer_size);
  Writen(fd, &tmp, sizeof(uint32_t));
  Writen(fd, (void*)buffer, buffer_size);
  return;
}

ssize_t
readmpz(int fd, mpz_t *x)
{
  char buffer[MAXBUF+1];
  size_t buffer_size, rc;
  uint32_t tmp;

  mpz_init(*x);
  bzero(buffer, sizeof(buffer));

  // Get size of the mpz
  rc = recv(fd, &tmp, sizeof(uint32_t), 0);
  if(rc <= 0) return rc;
  buffer_size = ntohl(tmp);

  // Get the mpz 
  buffer_size = Readn(fd, buffer, buffer_size);

  mpz_import(*x, buffer_size*sizeof(char), 1, sizeof(char), 0, 0, buffer);

  return buffer_size; 
}


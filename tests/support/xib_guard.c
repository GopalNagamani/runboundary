#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
 if (argc != 5) return 64;
 int denied=!strcmp(argv[1],"denied");
 for(int i=2;i<4;i++) {
   int fd=open(argv[i],O_RDONLY|O_NOFOLLOW), error=errno;
   if(fd>=0) close(fd);
   if(denied ? (fd>=0 || (error!=EPERM && error!=EACCES)) : fd<0) {
     fprintf(stderr,"file control %d failed: expected-denied=%d, fd=%d, errno=%d\n",i-1,denied,fd,error);
     return 70+i;
   }
 }
 int fd=socket(AF_INET,SOCK_STREAM,0);
 if(fd<0) {
   if(denied && (errno==EPERM || errno==EACCES)) return 0;
   fprintf(stderr,"socket creation failed: expected-denied=%d, errno=%d\n",denied,errno); return 75;
 }
 struct sockaddr_in address={0}; address.sin_family=AF_INET;
 address.sin_port=htons((unsigned short)atoi(argv[4])); inet_pton(AF_INET,"127.0.0.1",&address.sin_addr);
 int result=connect(fd,(struct sockaddr *)&address,sizeof(address)), error=errno; close(fd);
 if(denied ? (result<0 && (error==EPERM || error==EACCES)) : result==0) return 0;
 fprintf(stderr,"TCP control failed: expected-denied=%d, result=%d, errno=%d\n",denied,result,error); return 76;
}

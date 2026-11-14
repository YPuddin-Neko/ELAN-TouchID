#ifndef ELAN_AUTH_PROTOCOL_H
#define ELAN_AUTH_PROTOCOL_H

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

enum { ElanAuthRequest=1, ElanAuthProgress, ElanAuthMatch, ElanAuthNoMatch, ElanAuthError };
enum { ElanAuthMaxPayload=4096, ElanAuthMaxPassword=1024 };
#define ELAN_AUTH_TEST_RIGHT "io.github.hackintosh-tools.elan-unlock.test"

static inline void elan_auth_wipe(void *data, size_t length) {
    volatile unsigned char *p=data;
    while(length--) *p++=0;
}

static inline void elan_auth_path(uid_t uid, char path[104]) {
    snprintf(path,104,"/private/tmp/io.github.hackintosh-tools.elan-unlock.%u.sock",uid);
}

static inline int elan_auth_socket_options(int fd) {
    int yes=1;
    struct timeval timeout={30,0};
    return setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&yes,sizeof(yes))==0 &&
        setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0 &&
        setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))==0;
}

static inline int elan_auth_transfer(int fd, void *buffer, size_t length, int writing) {
    unsigned char *p=buffer;
    while(length) {
        ssize_t n=writing?send(fd,p,length,0):recv(fd,p,length,0);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) return 0;
        p+=n; length-=(size_t)n;
    }
    return 1;
}

static inline int elan_auth_send(int fd, uint32_t kind, const void *data, size_t length) {
    if(length>ElanAuthMaxPayload) return 0;
    uint32_t header[]={htonl(kind),htonl((uint32_t)length)};
    return elan_auth_transfer(fd,header,sizeof(header),1) &&
        elan_auth_transfer(fd,(void *)data,length,1);
}

static inline int elan_auth_receive(int fd, uint32_t *kind, unsigned char *data, size_t *length) {
    uint32_t header[2];
    if(!elan_auth_transfer(fd,header,sizeof(header),0)) return 0;
    *kind=ntohl(header[0]); *length=ntohl(header[1]);
    if(*length>ElanAuthMaxPayload || *kind<ElanAuthRequest || *kind>ElanAuthError) return 0;
    return elan_auth_transfer(fd,data,*length,0);
}

/* The username is NUL-terminated; password bytes occupy the rest of the frame. */
static inline int elan_auth_credentials(unsigned char *data, size_t length,
                                       const char *expectedUser, void **password, size_t *passwordLength) {
    unsigned char *end=memchr(data,0,length);
    if(!end || (size_t)(end-data)!=strlen(expectedUser) ||
       memcmp(data,expectedUser,(size_t)(end-data))) return 0;
    size_t n=length-(size_t)(end-data)-1;
    if(n==0 || n>ElanAuthMaxPassword || memchr(end+1,0,n)) return 0;
    *password=end+1; *passwordLength=n;
    return 1;
}
#endif

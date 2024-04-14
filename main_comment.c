#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "quick_sort.h"
#include "boyer_moore_search.h"

void usage() {
    printf("type host dns\n");
    printf("syntax : 1m-block <site list file>\n");
    printf("sample : 1m-block top-1m.txt\n");
}


char **read_csv_file(const char *path) {
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        printf("Can't open file\n");
        exit(EXIT_FAILURE);
    }

    // 초기 배열 크기 설정
    size_t initial_size = 10;
    size_t lines_count = 0;
    size_t lines_capacity = initial_size;

    // 문자열 배열 동적 할당
    char **lines = (char **)malloc(initial_size * sizeof(char *));
    if (lines == NULL) {
        printf("Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    char line[256];
    while (fgets(line, sizeof(line), file) != NULL) {
        // 첫 번째 쉼표의 위치 찾기
        char *comma_pos = strchr(line, ',');
        if (comma_pos != NULL) {
            // 필요에 따라 배열 크기 재조정
            if (lines_count == lines_capacity) {
                lines_capacity *= 2;
                lines = (char **)realloc(lines, lines_capacity * sizeof(char *));
                if (lines == NULL) {
                    printf("Memory allocation failed\n");
                    exit(EXIT_FAILURE);
                }
            }

            // 메모리 할당 및 문자열 복사
            size_t token_length = strlen(comma_pos + 1);
            lines[lines_count] = (char *)malloc((token_length + 1) * sizeof(char));
            if (lines[lines_count] == NULL) {
                printf("Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }
            strcpy(lines[lines_count], comma_pos + 1);

            // 개행 문자를 제거합니다.
            char *newline = strchr(lines[lines_count], '\n');
            if (newline != NULL) {
                *newline = '\0'; // 개행 문자를 NULL로 대체합니다.
            }

            lines_count++;
        }
    }

    fclose(file);
    // 퀵 정렬
    quick_sort(lines, 0, lines_count - 1);
    return lines;
}


void hex_to_ascii(const char *hex_data, char *ascii_data, int hex_len) {
    int i;
    for (i = 0; i < hex_len; i += 2) {
        // Convert two hexadecimal characters to a single ASCII character
        sscanf(hex_data + i, "%2hhx", &ascii_data[i / 2]);
    }
    // Add null terminator to the ASCII string
    ascii_data[i / 2] = '\0';
}


void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
        //printf("%c", buf[i]);
    }
    printf("\n");
}


static int my_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
    unsigned char *packet_data;
    int ret;
    int id;
    struct nfqnl_msg_packet_hdr *ph;
    
    printf("entering callback\n");
    
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocoe=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
    }
    
    ret = nfq_get_payload(nfa, &packet_data);
    if (ret >= 0) {
        printf("payload_len=%d\n", ret);
    }
    
    char **hosts = (char **)data;
    char pattern[ret+1];
    memcpy(pattern, packet_data, ret);
    pattern[ret] = '\0';
    int i;
    // 패턴 검색
    for (i = 0; hosts[i] != NULL; ++i) {
        int result = boyer_moore_search(hosts[i], strlen(hosts[i]), 0, pattern, ret);
        if (result != -1) {
            printf("Pattern found at index %d in string \"%s\"\n", result, hosts[i]-1);
            return nfq_set_verdict(qh, (u_int32_t)id, NF_DROP, 0, NULL);
        }
    }
    printf("\n");
    printf("packet accept\n");
    dump(packet_data, ret);
    return nfq_set_verdict(qh, (u_int32_t)id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char **argv) {
    if (argc != 2) {
        usage();
        return EXIT_FAILURE;
    }
    
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    
    char **hosts = read_csv_file(argv[1]);
    
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &my_callback, hosts);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }
    
    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

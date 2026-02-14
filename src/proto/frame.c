#include "frame.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

static int write_all(int fd, const void* buf, size_t len) {
    const unsigned char* p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void* buf, size_t len) {
    unsigned char* p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int FrameSend(int fd, msg_type_t type, const void* payload, uint32_t len) {
    frame_header_t hdr;
    hdr.payload_len = htonl(len);
    hdr.type = htons((uint16_t)type);
    hdr.version = PROTO_VER;
    hdr.flags = 0;

    if (write_all(fd, &hdr, sizeof(hdr)) != 0) return -1;
    if (len > 0 && payload != NULL) {
        if (write_all(fd, payload, len) != 0) return -1;
    }

    return 0;
}

int FrameRecv(int fd, frame_header_t* hdr, void** payload) {
    if (read_all(fd, hdr, sizeof(*hdr)) != 0) return -1;

    hdr->payload_len = ntohl(hdr->payload_len);
    hdr->type = ntohs(hdr->type);
    if (hdr->payload_len > 0) {
        void* buf = malloc(hdr->payload_len + 1);
        if (!buf) return -1;
        if (read_all(fd, buf, hdr->payload_len) != 0) {
            free(buf);
            return -1;
        }
        ((char*)buf)[hdr->payload_len] = '\0';
        *payload = buf;
    } else {
        *payload = NULL;
    }
    return 0;
}


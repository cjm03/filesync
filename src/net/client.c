#include "client.h"
#include "../proto/frame.h"
#include "../fs/scan.h"
#include "../fs/manifest.h"
#include "../common/log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

static int connect_to_host(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int RunClient(const char *root, const char *host, int port) {
    manifest_t local;
    ManifestInit(&local);

    if (ScanDirectory(root, &local) != 0) {
        LogError("Client: scan failed");
        ManifestFree(&local);
        return -1;
    }

    char* manifest_text = NULL;
    size_t manifest_len = 0;
    if (ManifestWriteToText(&local, &manifest_text, &manifest_len) != 0) {
        LogError("Client: manifest serialize failed");
        ManifestFree(&local);
        return -1;
    }

    int fd = connect_to_host(host, port);
    if (fd < 0) {
        LogError("Client: connect failed");
        free(manifest_text);
        ManifestFree(&local);
        return -1;
    }

    // HELLO
    if (FrameSend(fd, MSG_HELLO, NULL, 0) != 0) {
        close(fd);
        free(manifest_text);
        ManifestFree(&local);
        return -1;
    }

    // MANIFEST
    if (FrameSend(fd, MSG_MANIFEST, manifest_text, (uint32_t)manifest_len) != 0) {
        close(fd);
        free(manifest_text);
        ManifestFree(&local);
        return -1;
    }

    free(manifest_text);
    ManifestFree(&local);

    // Receive DIFF or ERR
    frame_header_t hdr;
    void *payload = NULL;
    if (FrameRecv(fd, &hdr, &payload) != 0) {
        close(fd);
        return -1;
    }

    if (hdr.type == MSG_DIFF && payload) {
        LogInfo("Diff received:\n%s", (char *)payload);
    } else if (hdr.type == MSG_ERR && payload) {
        LogError("Server error: %s", (char *)payload);
    }

    free(payload);
    close(fd);
    return 0;
}

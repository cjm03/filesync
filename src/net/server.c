#include "server.h"
#include "../proto/frame.h"
#include "../fs/scan.h"
#include "../fs/manifest.h"
#include "../sync/diff.h"
#include "../common/log.h"
// #include <asm-generic/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static int create_listen_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 1) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}





int RunServer(const char* root, int port) {
    int listen_fd = create_listen_socket(port);
    if (listen_fd < 0) {
        LogError("Server: listen failed");
        return -1;
    }

    LogInfo("Server listening on port %d", port);
    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        close(listen_fd);
        return -1;
    }

    frame_header_t hdr;
    void *payload = NULL;

    // Expect HELLO
    if (FrameRecv(client_fd, &hdr, &payload) != 0 || hdr.type != MSG_HELLO) {
        FrameSend(client_fd, MSG_ERR, "Expected HELLO", 14);
        close(client_fd);
        close(listen_fd);
        free(payload);
        return -1;
    }
    free(payload);

    // Expect MANIFEST
    if (FrameRecv(client_fd, &hdr, &payload) != 0 || hdr.type != MSG_MANIFEST) {
        FrameSend(client_fd, MSG_ERR, "Expected MANIFEST", 17);
        close(client_fd);
        close(listen_fd);
        free(payload);
        return -1;
    }

    manifest_t remote;
    ManifestInit(&remote);
    if (payload && ManifestReadFromText((const char *)payload, &remote) != 0) {
        FrameSend(client_fd, MSG_ERR, "Manifest parse error", 21);
        free(payload);
        ManifestFree(&remote);
        close(client_fd);
        close(listen_fd);
        return -1;
    }
    free(payload);

    // Scan local root
    manifest_t local;
    ManifestInit(&local);
    if (ScanDirectory(root, &local) != 0) {
        FrameSend(client_fd, MSG_ERR, "Scan failed", 11);
        ManifestFree(&local);
        ManifestFree(&remote);
        close(client_fd);
        close(listen_fd);
        return -1;
    }

    // Diff
    diff_t d;
    DiffInit(&d);
    if (DiffCompute(&local, &remote, &d) != 0) {
        FrameSend(client_fd, MSG_ERR, "Diff failed", 11);
        DiffFree(&d);
        ManifestFree(&local);
        ManifestFree(&remote);
        close(client_fd);
        close(listen_fd);
        return -1;
    }

    char* diff_text = NULL;
    size_t diff_len = 0;
    if (DiffWrite(&d, "/tmp/sync_diff.txt") == 0) {
        FILE* f = fopen("/tmp/sync_diff.txt", "r");
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            diff_text = malloc(sz + 1);
            if (diff_text) {
                fread(diff_text, 1, sz, f);
                diff_text[sz] = '\0';
                diff_len = (size_t)sz;
            }
            fclose(f);
        }
    }

    if (diff_text) {
        FrameSend(client_fd, MSG_DIFF, diff_text, (uint32_t)diff_len);
        free(diff_text);
    } else {
        FrameSend(client_fd, MSG_ERR, "Diff serialize failed", 22);
    }


    DiffFree(&d);
    ManifestFree(&local);
    ManifestFree(&remote);
    close(client_fd);
    close(listen_fd);
    return 0;
}
























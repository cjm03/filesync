#include "client.h"
#include "../proto/frame.h"
#include "../fs/scan.h"
#include "../fs/manifest.h"
#include "../common/log.h"
#include "../common/sha256.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#define CHUNK_SIZE 65536
#define PATHBUF 4096

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

static uint64_t htonll(uint64_t v) {
    uint32_t hi = htonl((uint32_t)(v >> 32));
    uint32_t lo = htonl((uint32_t)(v & 0xFFFFFFFFU));
    return ((uint64_t)lo << 32) | hi;
}

static const manifest_entry_t* find_entry(const manifest_t* m, const char* path) {
    for (size_t i = 0; i < m->count; i++) {
        if (strcmp(m->entries[i].path, path) == 0) return &m->entries[i];
    }
    return NULL;
}

static int send_file(int fd, const char* root, const manifest_entry_t* e) {
    char fullpath[PATHBUF];
    snprintf(fullpath, sizeof(fullpath), "%s/%s", root, e->path);

    FILE* f = fopen(fullpath, "rb");
    if (!f) {
        LogError("Client: failed to open %s", fullpath);
        return -1;
    }

    uint16_t path_len = (uint16_t)strlen(e->path);
    uint64_t size_net = htonll((uint64_t)e->size);

    size_t payload_len = sizeof(uint16_t) + path_len + sizeof(uint64_t) + SHA256_DIGEST_SIZE;
    unsigned char *payload = malloc(payload_len);
    if (!payload) {
        fclose(f);
        return -1;
    }

    uint16_t path_len_net = htons(path_len);
    memcpy(payload, &path_len_net, sizeof(uint16_t));
    memcpy(payload + sizeof(uint16_t), e->path, path_len);
    memcpy(payload + sizeof(uint16_t) + path_len, &size_net, sizeof(uint64_t));
    memcpy(payload + sizeof(uint16_t) + path_len + sizeof(uint64_t), e->hash, SHA256_DIGEST_SIZE);

    if (FrameSend(fd, MSG_FILE_BEGIN, payload, (uint32_t)payload_len) != 0) {
        free(payload);
        fclose(f);
        return -1;
    }
    free(payload);

    unsigned char buf[CHUNK_SIZE];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (FrameSend(fd, MSG_FILE_DATA, buf, (uint32_t)n) != 0) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);

    if (FrameSend(fd, MSG_FILE_END, NULL, 0) != 0) return -1;

    // Expect OK/ERR
    frame_header_t hdr;
    void *resp = NULL;
    if (FrameRecv(fd, &hdr, &resp) != 0) return -1;

    if (hdr.type == MSG_ERR && resp) {
        LogError("Server error: %s", (char*)resp);
        free(resp);
        return -1;
    }

    free(resp);
    return 0;
}

static int send_files_from_diff(int fd, const char* root, const manifest_t* local, const char* diff_text) {
    const char *p = diff_text;
    while (*p) {
        char action[16];
        char path[PATHBUF];

        int n = sscanf(p, "%15s\t%4095[^\n]", action, path);
        if (n != 2) break;

        if (strcmp(action, "NEW") == 0 || strcmp(action, "CHANGED") == 0) {
            const manifest_entry_t* e = find_entry(local, path);
            if (!e) {
                LogError("Client: missing entry for %s", path);
                return -1;
            }
            if (send_file(fd, root, e) != 0) return -1;
        }

        const char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
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
    // ManifestFree(&local);

    // Receive DIFF or ERR
    frame_header_t hdr;
    void *payload = NULL;
    if (FrameRecv(fd, &hdr, &payload) != 0) {
        close(fd);
        ManifestFree(&local);
        return -1;
    }

    if (hdr.type == MSG_DIFF && payload) {
        LogInfo("Diff received:\n%s", (char *)payload);
        if (send_files_from_diff(fd, root, &local, (char*)payload) != 0) {
            free(payload);
            ManifestFree(&local);
            close(fd);
            return -1;
        }
    } else if (hdr.type == MSG_ERR && payload) {
        LogError("Server error: %s", (char *)payload);
    }

    free(payload);
    FrameSend(fd, MSG_DONE, NULL, 0);
    ManifestFree(&local);
    close(fd);
    return 0;
}

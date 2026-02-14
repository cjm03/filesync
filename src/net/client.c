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

static char *manifest_to_text(const manifest_t *m, size_t *out_len) {
    size_t buf_cap = 1024;
    size_t buf_len = 0;
    char *buf = malloc(buf_cap);
    if (!buf) return NULL;

    for (size_t i = 0; i < m->count; i++) {
        const manifest_entry_t *e = &m->entries[i];
        const char *type =
            (e->type == ENTRY_FILE) ? "FILE" :
            (e->type == ENTRY_DIR) ? "DIR" :
            (e->type == ENTRY_SYMLINK) ? "SYMLINK" : "OTHER";

        size_t line_len = strlen(type) + 1 + 32 + 1 + 32 + 1 + strlen(e->path) + 1;
        if (buf_len + line_len + 1 > buf_cap) {
            buf_cap *= 2;
            char *tmp = realloc(buf, buf_cap);
            if (!tmp) { free(buf); return NULL; }
            buf = tmp;
        }

        buf_len += (size_t)snprintf(buf + buf_len, buf_cap - buf_len,
            "%s\t%zu\t%lld\t%s\n", type, e->size, (long long)e->mtime, e->path);
    }

    *out_len = buf_len;
    return buf;
}

int RunClient(const char *root, const char *host, int port) {
    manifest_t local;
    ManifestInit(&local);

    if (ScanDirectory(root, &local) != 0) {
        LogError("Client: scan failed");
        ManifestFree(&local);
        return -1;
    }

    size_t manifest_len = 0;
    char *manifest_text = manifest_to_text(&local, &manifest_len);
    if (!manifest_text) {
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

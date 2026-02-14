#include "server.h"
#include "../proto/frame.h"
#include "../fs/scan.h"
#include "../fs/manifest.h"
#include "../sync/diff.h"
#include "../common/log.h"
#include <asm-generic/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static int manifest_read_text(const char *text, manifest_t *m) {
    // Reuse your existing manifest parser if you have one.
    // This is a placeholder simple parser (TYPE\tSIZE\tMTIME\tPATH).
    const char *p = text;
    while (*p) {
        char type_str[32];
        size_t size = 0;
        long long mtime_ll = 0;
        char path_buf[4096];

        int n = sscanf(p, "%31s\t%zu\t%lld\t%4095[^\n]", type_str, &size, &mtime_ll, path_buf);
        if (n != 4) break;

        manifest_entry_t e = {0};
        e.size = size;
        e.mtime = (time_t)mtime_ll;
        e.path = strdup(path_buf);

        if (strcmp(type_str, "FILE") == 0) e.type = ENTRY_FILE;
        else if (strcmp(type_str, "DIR") == 0) e.type = ENTRY_DIR;
        else if (strcmp(type_str, "SYMLINK") == 0) e.type = ENTRY_SYMLINK;
        else e.type = ENTRY_OTHER;

        if (ManifestAdd(m, &e) != 0) {
            free(e.path);
            return -1;
        }

        // advance to next line
        const char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
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
    if (payload && manifest_read_text((const char *)payload, &remote) != 0) {
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

    // Write diff to memory
    // (Simple: write to tmp buffer using a growing string)
    size_t buf_cap = 1024;
    size_t buf_len = 0;
    char *diff_buf = malloc(buf_cap);
    if (!diff_buf) {
        FrameSend(client_fd, MSG_ERR, "Alloc failed", 12);
    } else {
        for (size_t i = 0; i < d.count; i++) {
            const char *action =
                (d.items[i].action == ACTION_NEW) ? "NEW" :
                (d.items[i].action == ACTION_CHANGED) ? "CHANGED" : "DELETED";

            const char *path = d.items[i].entry->path;
            size_t line_len = strlen(action) + 1 + strlen(path) + 1;

            if (buf_len + line_len + 1 > buf_cap) {
                buf_cap *= 2;
                char *tmp = realloc(diff_buf, buf_cap);
                if (!tmp) { free(diff_buf); diff_buf = NULL; break; }
                diff_buf = tmp;
            }

            if (diff_buf) {
                buf_len += (size_t)snprintf(diff_buf + buf_len, buf_cap - buf_len, "%s\t%s\n", action, path);
            }
        }
        if (diff_buf) {
            FrameSend(client_fd, MSG_DIFF, diff_buf, (uint32_t)buf_len);
            free(diff_buf);
        }
    }

    DiffFree(&d);
    ManifestFree(&local);
    ManifestFree(&remote);
    close(client_fd);
    close(listen_fd);
    return 0;
}
























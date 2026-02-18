#include "server.h"
#include "../proto/frame.h"
#include "../fs/scan.h"
#include "../fs/manifest.h"
#include "../sync/diff.h"
#include "../common/log.h"
#include "../common/sha256.h"
// #include <asm-generic/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>

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

static uint64_t ntohll(uint64_t v) {
    uint32_t lo = ntohl((uint32_t)(v >> 32));
    uint32_t hi = ntohl((uint32_t)(v & 0xFFFFFFFFU));
    return ((uint64_t)hi << 32) | lo;
}

static int ensure_parent_dirs(const char* path) {
    char tmp[PATHBUF];
    snprintf(tmp, sizeof(tmp), "%s", path);

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return 0;
}

static int recv_file(int fd, const char* root, const unsigned char* begin_payload, uint32_t len) {
    if (len < sizeof(uint16_t) + sizeof(uint64_t) + SHA256_DIGEST_SIZE) return -1;

    const unsigned char* p = begin_payload;
    uint16_t path_len = 0;
    memcpy(&path_len, p, sizeof(uint16_t));
    path_len = ntohs(path_len);
    p += sizeof(uint16_t);

    if ((size_t)path_len + sizeof(uint64_t) + SHA256_DIGEST_SIZE > len) return -1;

    char relpath[PATHBUF];
    if (path_len >= sizeof(relpath)) return -1;
    memcpy(relpath, p, path_len);
    relpath[path_len] = '\0';
    p += path_len;

    uint64_t size_net = 0;
    memcpy(&size_net, p, sizeof(uint64_t));
    uint64_t file_size = ntohll(size_net);
    p += sizeof(uint64_t);

    unsigned char expected_hash[SHA256_DIGEST_SIZE];
    memcpy(expected_hash, p, SHA256_DIGEST_SIZE);

    size_t root_len = strlen(root);
    size_t rel_len = strlen(relpath);
    if (root_len + 1 + rel_len + 1 > sizeof((char[PATHBUF]){0})) return -1;

    char fullpath[PATHBUF];
    int n = snprintf(fullpath, sizeof(fullpath), "%s/%s", root, relpath);
    if (n < 0 || (size_t)n >= sizeof(fullpath)) return -1;

    const char* tmp_suffix = "/.tmp.";
    size_t tmp_len = strlen(tmp_suffix) + 20;
    if ((size_t)n + tmp_len + 1 > sizeof((char[PATHBUF]){0})) return -1;

    char tmppath[PATHBUF];
    int m = snprintf(tmppath, sizeof(tmppath), "%s/.tmp.%d", fullpath, getpid());
    if (m < 0 || (size_t)m >= sizeof(tmppath)) return -1;

    ensure_parent_dirs(fullpath);

    FILE* f = fopen(tmppath, "wb");
    if (!f) return -1;

    sha256_t ctx;
    sha256_init(&ctx);

    uint64_t total = 0;

    while (1) {
        frame_header_t hdr;
        void* payload = NULL;
        if (FrameRecv(fd, &hdr, &payload) != 0) {
            fclose(f);
            free(payload);
            return -1;
        }

        if (hdr.type == MSG_FILE_DATA) {
            if (payload && hdr.payload_len > 0) {
                fwrite(payload, 1, hdr.payload_len, f);
                sha256_update(&ctx, payload, hdr.payload_len);
                total += hdr.payload_len;
            }
            free(payload);
        } else if (hdr.type == MSG_FILE_END) {
            free(payload);
            break;
        } else {
            free(payload);
            fclose(f);
            return -1;
        }
    }

    fflush(f);
    fsync(fileno(f));
    fclose(f);

    unsigned char actual_hash[SHA256_DIGEST_SIZE];
    sha256_final(&ctx, actual_hash);

    if (total != file_size || memcmp(actual_hash, expected_hash, SHA256_DIGEST_SIZE) != 0) {
        unlink(tmppath);
        return -1;
    }

    if (rename(tmppath, fullpath) != 0) {
        unlink(tmppath);
        return -1;
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

    for (;;) {
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
            // close(listen_fd);
            free(payload);
            return -1;
        }
        free(payload);

        // Expect MANIFEST
        if (FrameRecv(client_fd, &hdr, &payload) != 0 || hdr.type != MSG_MANIFEST) {
            FrameSend(client_fd, MSG_ERR, "Expected MANIFEST", 17);
            close(client_fd);
            // close(listen_fd);
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
            // close(listen_fd);
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
            // close(listen_fd);
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
            // close(listen_fd);
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
            DiffFree(&d);
            ManifestFree(&local);
            ManifestFree(&remote);
            close(client_fd);
            // close(listen_fd);
            return -1;
        }

        // Receive files until DONE
        while (1) {
            void* payload2 = NULL;
            if (FrameRecv(client_fd, &hdr, &payload2) != 0) break;

            if (hdr.type == MSG_FILE_BEGIN) {
                if (recv_file(client_fd, root, (const unsigned char*)payload2, hdr.payload_len) != 0) {
                    FrameSend(client_fd, MSG_ERR, "File receive failed", 20);
                    free(payload2);
                    break;
                }
                FrameSend(client_fd, MSG_OK, NULL, 0);
                free(payload2);
            } else if (hdr.type == MSG_DONE) {
                free(payload2);
                break;
            } else {
                free(payload2);
                break;
            }
        }

        DiffFree(&d);
        ManifestFree(&local);
        ManifestFree(&remote);
        close(client_fd);
    }

    close(listen_fd);
    return 0;
}
























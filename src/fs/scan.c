#define _DEFAULT_SOURCE
#include "scan.h"
#include "../common/log.h"
#include "../common/sha256.h"
#include "manifest.h"
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static int scan_recursive(const char* root, const char* rel, manifest_t* m) {
    char path[PATHBUF];
    if (rel[0] == '\0') {
        snprintf(path, sizeof(path), "%s", root);
    } else {
        snprintf(path, sizeof(path), "%s/%s", root, rel);
    }

    DIR* dir = opendir(path);
    if (!dir) return -1;

    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        char child_rel[PATHBUF];
        if (rel[0] == '\0') {
            snprintf(child_rel, sizeof(child_rel), "%s", ent->d_name);
        } else {
            snprintf(child_rel, sizeof(child_rel), "%s/%s", rel, ent->d_name);
        }

        char child_path[PATHBUF + 1];
        snprintf(child_path, sizeof(child_path), "%s/%s", root, child_rel);

        struct stat st;
        if (lstat(child_path, &st) != 0) {
            LogError("lstat failed: %s", child_path);
            continue;
        }

        manifest_entry_t e = {0};
        e.path = strdup(child_rel);
        e.size = (size_t)st.st_size;
        e.mtime = st.st_mtime;

        if (S_ISREG(st.st_mode)) {

            e.type = ENTRY_FILE;
            FILE* f = fopen(child_path, "rb");
            if (f == NULL) {
                fprintf(stderr, "Cannot open file: %s\n", child_path);
                e.has_hash = 0;
            } else {
                sha256_t ctx;
                unsigned char buffer[512];
                size_t bRead;
                sha256_init(&ctx);
                while ((bRead = fread(buffer, 1, sizeof(buffer), f)) != 0) {
                    sha256_update(&ctx, buffer, bRead);
                }
                sha256_final(&ctx, e.hash);
                e.has_hash = 1;

                // for (int i = 0; i < SHA256_DIGEST_SIZE; i++) printf("%02x ", e.hash[i]);
                // printf("\n");
                
                fclose(f);

            }

        } else if (S_ISDIR(st.st_mode)) {
            
            e.type = ENTRY_DIR;

        } else if (S_ISLNK(st.st_mode)) {

            e.type = ENTRY_SYMLINK;

        } else {

            e.type = ENTRY_OTHER;

        }

        if (ManifestAdd(m, &e) != 0) {
            free(e.path);
            closedir(dir);
            return -1;
        }

        if (S_ISDIR(st.st_mode)) {
            if (scan_recursive(root, child_rel, m) != 0) {
                closedir(dir);
                return -1;
            }
        }
    }
    closedir(dir);
    return 0;
}

int ScanDirectory(const char* root, manifest_t* out_manifest) {
    return scan_recursive(root, "", out_manifest);
}

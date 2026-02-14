#include "manifest.h"
#include "../common/sha256.h"
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void hash_to_hex(const unsigned char hash[SHA256_DIGEST_SIZE], char* out) {
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        sprintf(out + (i * 2), "%02x", hash[i]);
    }
    out[SHA256_DIGEST_SIZE * 2] = '\0';
}

static int hex_to_hash(const char* hex, unsigned char out[SHA256_DIGEST_SIZE]) {
    if (strlen(hex) != SHA256_DIGEST_SIZE * 2) return -1;
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        unsigned int v;
        if (sscanf(hex + (i * 2), "%2x", &v) != 1) return -1;
        out[i] = (unsigned char)v;
    }
    return 0;
}

void ManifestInit(manifest_t* m) {
    m->entries = NULL;
    m->count = 0;
    m->capacity = 0;
}

void ManifestFree(manifest_t* m) {
    for (size_t i = 0; i < m->count; i++) {
        free(m->entries[i].path);
    }
    free(m->entries);
}

int ManifestAdd(manifest_t* m, const manifest_entry_t* e) {
    if (m->count == m->capacity) {
        size_t new_cap = m->capacity == 0 ? 64 : m->capacity * 2;
        manifest_entry_t* new_entries = realloc(m->entries, new_cap * sizeof(*new_entries));
        if (!new_entries) return -1;
        m->entries = new_entries;
        m->capacity = new_cap;
    }
    m->entries[m->count++] = *e;
    return 0;
}

static const char* type_to_string(entry_type_t t) {
    switch (t) {
        case ENTRY_FILE: return "FILE";
        case ENTRY_DIR: return "DIR";
        case ENTRY_SYMLINK: return "SYMLINK";
        default: return "OTHER";
    }
}

int ManifestWrite(const manifest_t* m, const char* out_path) {
    FILE* f = fopen(out_path, "w");
    if (!f) return -1;
    for (size_t i = 0; i < m->count; i++) {
        const manifest_entry_t* e = &m->entries[i];

        const char* type = 
            (e->type == ENTRY_FILE) ? "FILE" : (e->type == ENTRY_DIR) ? "DIR" : (e->type == ENTRY_SYMLINK) ? "SYMLINK" : "OTHER";

        char hash_hex[SHA256_DIGEST_SIZE * 2 + 1];
        if (e->has_hash) hash_to_hex(e->hash, hash_hex);
        else snprintf(hash_hex, sizeof(hash_hex), "-");

        fprintf(f, "%s\t%zu\t%lld\t%s\t%s\n", type, e->size, (long long)e->mtime, hash_hex, e->path);
        printf("%s\t%zu\t%lld\t%s\t%s\n", type_to_string(e->type), e->size, (long long)e->mtime, e->hash, e->path);
        // fprintf(f, "%s,%d\t%zu\t%lld\t%s\t%s\n", type_to_string(e->type), e->has_hash, e->size, (long long)e->mtime, e->path, e->hash);
        // printf("%s,%d\t%zu\t%lld\t%s\t%s\n", type_to_string(e->type), e->has_hash, e->size, (long long)e->mtime, e->path, e->hash);
    }
    fclose(f);
    return 0;
}


int ManifestRead(const char* path, manifest_t* m) {
    FILE* f = fopen(path, "r");
    if (!f) return -1;

    char line[8192];
    while (fgets(line, sizeof(line), f)) {
        manifest_entry_t e = {0};
        char type_string[32];
        char hash_hex[SHA256_DIGEST_SIZE * 2 + 2];
        long long mtime_ll;
        char path_buf[4096];

        if (sscanf(line, "%31s\t%zu\t%lld\t%64s\t%4095[^\n]", type_string, &e.size, &mtime_ll, hash_hex, path_buf) != 5) {
            fclose(f);
            return -1;
        }

        e.mtime = (time_t)mtime_ll;
        e.path = strdup(path_buf);

        if (strcmp(type_string, "FILE") == 0) e.type = ENTRY_FILE;
        else if (strcmp(type_string, "DIR") == 0) e.type = ENTRY_DIR;
        else if (strcmp(type_string, "SYMLINK") == 0) e.type = ENTRY_SYMLINK;
        else e.type = ENTRY_OTHER;

        if (strcmp(hash_hex, "-") == 0) {
            e.has_hash = false;
        } else if (hex_to_hash(hash_hex, e.hash) == 0) {
            e.has_hash = true;
        } else {
            e.has_hash = false;
        }

        if (ManifestAdd(m, &e) != 0) {
            free(e.path);
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}

int ManifestReadFromText(const char* text, manifest_t* m) {
    const char* p = text;
    while (*p) {
        manifest_entry_t e = {0};
        char type_string[32];
        char hash_hex[SHA256_DIGEST_SIZE * 2 + 2];
        long long mtime_ll;
        char path_buf[4096];

        int n = sscanf(p, "%31s\t%zu\t%lld\t%64s\t%4095[^\n]", type_string, &e.size, &mtime_ll, hash_hex, path_buf);
        if (n != 5) break;

        e.mtime = (time_t)mtime_ll;
        e.path = strdup(path_buf);

        if (strcmp(type_string, "FILE") == 0) e.type = ENTRY_FILE;
        else if (strcmp(type_string, "DIR") == 0) e.type = ENTRY_DIR;
        else if (strcmp(type_string, "SYMLINK") == 0) e.type = ENTRY_SYMLINK;
        else e.type = ENTRY_OTHER;

        if (strcmp(hash_hex, "-") == 0) {
            e.has_hash = false;
        } else if (hex_to_hash(hash_hex, e.hash) == 0) {
            e.has_hash = true;
        } else {
            e.has_hash = false;
        }

        if (ManifestAdd(m, &e) != 0) {
            free(e.path);
            return -1;
        }

        const char* nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

int ManifestWriteToText(const manifest_t* m, char** out_text, size_t* out_len) {
    size_t buf_cap = 1024;
    size_t buf_len = 0;
    char *buf = malloc(buf_cap);
    if (!buf) return -1;

    for (size_t i = 0; i < m->count; i++) {
        const manifest_entry_t* e = &m->entries[i];

        const char* type =
            (e->type == ENTRY_FILE) ? "FILE" :
            (e->type == ENTRY_DIR) ? "DIR" :
            (e->type == ENTRY_SYMLINK) ? "SYMLINK" : "OTHER";

        char hash_hex[SHA256_DIGEST_SIZE * 2 + 1];
        if (e->has_hash) hash_to_hex(e->hash, hash_hex);
        else snprintf(hash_hex, sizeof(hash_hex), "-");

        size_t line_len = strlen(type) + 1 + 32 + 1 + 32 + 1 + strlen(hash_hex) + 1 + strlen(e->path) + 1;
        if (buf_len + line_len + 1 > buf_cap) {
            buf_cap *= 2;
            char *tmp = realloc(buf, buf_cap);
            if (!tmp) { free(buf); return -1; }
            buf = tmp;
        }

        buf_len += (size_t)snprintf(buf + buf_len, buf_cap - buf_len,
            "%s\t%zu\t%lld\t%s\t%s\n", type, e->size, (long long)e->mtime, hash_hex, e->path);
    }

    *out_text = buf;
    *out_len = buf_len;
    return 0;
}

































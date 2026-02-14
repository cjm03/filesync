#include "manifest.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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
        fprintf(f, "%s\t%zu\t%lld\t%s\n", type_to_string(e->type), e->size, (long long)e->mtime, e->path);
        // fprintf(f, "%s,%d\t%zu\t%lld\t%s\t%s\n", type_to_string(e->type), e->has_hash, e->size, (long long)e->mtime, e->path, e->hash);
        // printf("%s,%d\t%zu\t%lld\t%s\t%s\n", type_to_string(e->type), e->has_hash, e->size, (long long)e->mtime, e->path, e->hash);
    }
    fclose(f);
    return 0;
}

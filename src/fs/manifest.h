#ifndef MANIFEST_H
#define MANIFEST_H

#include <stddef.h>
#include <stdbool.h>
#include <time.h>

typedef enum {
    ENTRY_FILE,
    ENTRY_DIR,
    ENTRY_SYMLINK,
    ENTRY_OTHER
} entry_type_t;

typedef struct {
    char* path;
    entry_type_t type;
    size_t size;
    time_t mtime;
    unsigned char hash[32];
    bool has_hash;
} manifest_entry_t;

typedef struct {
    manifest_entry_t* entries;
    size_t count;
    size_t capacity;
} manifest_t;

void ManifestInit(manifest_t* m);
void ManifestFree(manifest_t* m);
int ManifestAdd(manifest_t* m, const manifest_entry_t* e);
int ManifestWrite(const manifest_t* m, const char* out_path);

#endif // MANIFEST_H

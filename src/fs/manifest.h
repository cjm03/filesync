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

// Initialize a manifest_t structure
void ManifestInit(manifest_t* m);

// Free a manifest_t structure
void ManifestFree(manifest_t* m);

// Add an entry (manifest_entry_t) to a manifest_t structure
int ManifestAdd(manifest_t* m, const manifest_entry_t* e);

// Write all entries of a manifest to file located at out_path
int ManifestWrite(const manifest_t* m, const char* out_path);
// Read all manifest entries from a file located at path to a manifest_t structure
int ManifestRead(const char* path, manifest_t* m);

// Write all manifest entries to a buffer
int ManifestWriteToText(const manifest_t* m, char** out_text, size_t* out_len);
// Read all manifest entries from a buffer to a manifest_t structure
int ManifestReadFromText(const char* text, manifest_t* m);

#endif // MANIFEST_H

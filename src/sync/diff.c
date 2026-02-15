// diff.c
#include "../common/log.h"
#include "../fs/manifest.h"
#include "../common/sha256.h"
#include "diff.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void DiffInit(diff_t* d) {
    d->items = NULL;
    d->count = 0;
    d->capacity = 0;
}

void DiffFree(diff_t* d) {
    for (size_t i = 0; i < d->count; i++) free(d->items[i].entry.path);
    free(d->items);
}

int DiffAdd(diff_t* d, diff_action_t action, const manifest_entry_t* entry) {
    if (d->count == d->capacity) {
        size_t newcap = d->capacity == 0 ? 64 : d->capacity * 2;
        diff_item_t* newitems = realloc(d->items, newcap * sizeof(*newitems));
        if (!newitems) return -1;
        d->items = newitems;
        d->capacity = newcap;
    }
    d->items[d->count].action = action;
    d->items[d->count].entry = *entry;
    d->items[d->count].entry.path = strdup(entry->path);
    if (!d->items[d->count].entry.path) return -1;
    d->count++;
    return 0;
}

static int entry_compare(const void* a, const void* b) {
    const manifest_entry_t* ea = (const manifest_entry_t*)a;
    const manifest_entry_t* eb = (const manifest_entry_t*)b;
    return strcmp(ea->path, eb->path);
}

static void manifest_sort(manifest_t* m) {
    qsort(m->entries, m->count, sizeof(manifest_entry_t), entry_compare);
}

static int hashes_differ(const manifest_entry_t* a, const manifest_entry_t* b) {
    if (!a->has_hash || !b->has_hash) return 0;
    return memcmp(a->hash, b->hash, SHA256_DIGEST_SIZE) != 0;
}

static int entries_differ(const manifest_entry_t* local, const manifest_entry_t* remote) {
    if (local->type != remote->type) return 1;
    if (local->size != remote->size) return 1;
    if (local->mtime != remote->mtime) return 1;

    if (hashes_differ(local, remote)) return 1;

    return 0;
}

int DiffCompute(const manifest_t* local, const manifest_t* remote, diff_t* out_diff) {
    manifest_t copylocal, copyremote;
    ManifestInit(&copylocal);
    ManifestInit(&copyremote);

    for (size_t i = 0; i < local->count; i++) {
        manifest_entry_t e = local->entries[i];
        e.path = strdup(e.path);
        if (ManifestAdd(&copylocal, &e) != 0) {
            ManifestFree(&copylocal);
            ManifestFree(&copyremote);
            return -1;
        }
    }

    for (size_t i = 0; i < remote->count; i++) {
        manifest_entry_t e = remote->entries[i];
        e.path = strdup(e.path);
        if (ManifestAdd(&copyremote, &e) != 0) {
            ManifestFree(&copylocal);
            ManifestFree(&copyremote);
            return -1;
        }
    }

    manifest_sort(&copylocal);
    manifest_sort(&copyremote);

    size_t i = 0, j = 0;
    while (i < copylocal.count || j < copyremote.count) {
        if (i >= copylocal.count) {
            DiffAdd(out_diff, ACTION_DELETED, &copyremote.entries[j]);
            j++;
        } else if (j >= copyremote.count) {
            DiffAdd(out_diff, ACTION_NEW, &copylocal.entries[i]);
            i++;
        } else {
            int cmp = strcmp(copylocal.entries[i].path, copyremote.entries[j].path);
            if (cmp < 0) {
                DiffAdd(out_diff, ACTION_NEW, &copylocal.entries[i]);
                i++;
            } else if (cmp > 0) {
                DiffAdd(out_diff, ACTION_DELETED, &copyremote.entries[j]);
                j++;
            } else {
                if (entries_differ(&copylocal.entries[i], &copyremote.entries[j])) {
                    DiffAdd(out_diff, ACTION_CHANGED, &copylocal.entries[i]);
                }
                i++;
                j++;
            }
        }
    }
    ManifestFree(&copylocal);
    ManifestFree(&copyremote);
    return 0;

}

static const char* action_to_string(diff_action_t a) {
    switch (a) {
        case ACTION_NEW: return "NEW";
        case ACTION_CHANGED: return "CHANGED";
        case ACTION_DELETED: return "DELETED";
        default: return "UNKNOWN";
    }
}

int DiffWrite(const diff_t* d, const char* out_path) {
    FILE* f = fopen(out_path, "w");
    if (!f) return -1;
    for (size_t i = 0; i < d->count; i++) {
        const diff_item_t* item = &d->items[i];
        fprintf(f, "%s\t%s\n", action_to_string(item->action), item->entry.path);
    }
    fclose(f);
    return 0;
}
























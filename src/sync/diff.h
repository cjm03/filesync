#ifndef DIFF_H
#define DIFF_H

#include "../fs/manifest.h"

typedef enum {
    ACTION_NEW,
    ACTION_CHANGED,
    ACTION_DELETED
} diff_action_t;

typedef struct {
    diff_action_t action;
    manifest_entry_t* entry; // ptr to entry in one of the manifests
} diff_item_t;

typedef struct {
    diff_item_t* items;
    size_t count;
    size_t capacity;
} diff_t;

void DiffInit(diff_t* d);
void DiffFree(diff_t* d);
int DiffAdd(diff_t* d, diff_action_t action, manifest_entry_t* entry);

/*
    Compute diff between local and remote manifests
    local = source , remote = destination
*/
int DiffCompute(const manifest_t* local, const manifest_t* remote, diff_t* out_diff);
int DiffWrite(const diff_t* d, const char* out_path);

#endif

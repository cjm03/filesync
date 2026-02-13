#ifndef SCAN_H
#define SCAN_H

#include "manifest.h"

#define PATHBUF 4096

int ScanDirectory(const char* root, manifest_t* out_manifest);

#endif // SCAN_H

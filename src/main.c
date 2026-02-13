#include "common/log.h"
#include "fs/scan.h"
#include "fs/manifest.h"
#include <string.h>
#include <stdio.h>

static void usage(void) {
    printf("Usage:\n");
    printf("   filesync --scan <path> --out <file>\n");
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        usage();
        return 1;
    }

    const char* scanpath = NULL;
    const char* outpath = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--scan") == 0 && i + 1 < argc) {
            scanpath = argv[++i];
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            outpath = argv[++i];
        }
    }

    if (!scanpath || !outpath) {
        usage();
        return 1;
    }

    manifest_t m;
    ManifestInit(&m);

    if (ScanDirectory(scanpath, &m) != 0) {
        LogError("Scan failed");
        ManifestFree(&m);
        return 1;
    }

    if (ManifestWrite(&m, outpath) != 0) {
        LogError("Failed to write manifest");
        ManifestFree(&m);
        return 1;
    }

    LogInfo("Manifest written to %s", outpath);
    ManifestFree(&m);
    return 0;
}

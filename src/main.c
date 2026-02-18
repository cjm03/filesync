#include "common/log.h"
#include "fs/scan.h"
#include "fs/manifest.h"
#include "sync/diff.h"
#include "net/server.h"
#include "net/client.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static void usage(void) {
    printf("Usage:\n");
    printf("   filesync --scan <path> --out <file>\n");
    printf("   filesync --diff <local manifest> <remote manifest> --out <diff file>\n");
    printf("   filesync --serve --root <path> --port 8443\n");
    printf("   filesync --sync --root <path> --host <ip> --port 8443\n");
}


int main(int argc, char* argv[]) {
    if (argc < 5) {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "--serve") == 0) {
        const char* root = NULL;
        int port = 8443;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) root = argv[++i];
            else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        }
        if (!root) {
            usage();
            return 1;
        }
        return RunServer(root, port);
    }

    if (strcmp(argv[1], "--sync") == 0) {
        const char *root = NULL;
        const char *host = NULL;
        int port = 8443;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) root = argv[++i];
            else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) host = argv[++i];
            else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        }
        if (!root || !host) {
            usage(); 
            return 1; 
        }
        return RunClient(root, host, port);
    }

    if (strcmp(argv[1], "--scan") == 0) {
        if (argc < 5) {
            usage();
            return 1;
        }
        const char* scanpath = NULL;
        const char* outpath = NULL;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
                outpath = argv[++i];
            } else if (!scanpath) {
                scanpath = argv[i];
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

    } else if (strcmp(argv[1], "--diff") == 0) {
        if (argc < 5) {
            usage();
            return 1;
        }

        const char* localpath = argv[2];
        const char* remotepath = argv[3];
        const char* outpath = NULL;

        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
                outpath = argv[++i];
            }
        }

        if (!outpath) {
            usage();
            return 1;
        }

        manifest_t local, remote;
        ManifestInit(&local);
        ManifestInit(&remote);

        if (ManifestRead(localpath, &local) != 0) {
            LogError("Failed reading local manifest: %s", localpath);
            ManifestFree(&local);
            ManifestFree(&remote);
            return 1;
        }

        if (ManifestRead(remotepath, &remote) != 0) {
            LogError("Failed reading remote manifest: %s", remotepath);
            ManifestFree(&local);
            ManifestFree(&remote);
            return 1;
        }

        diff_t d;
        DiffInit(&d);

        if (DiffCompute(&local, &remote, &d) != 0) {
            LogError("Failed to compute diff");
            DiffFree(&d);
            ManifestFree(&local);
            ManifestFree(&remote);
            return 1;
        }

        if (DiffWrite(&d, outpath) != 0) {
            LogError("Failed to write diff");
            DiffFree(&d);
            ManifestFree(&local);
            ManifestFree(&remote);
            return 1;
        }

        LogInfo("Diff written to %s (%zu changes)", outpath, d.count);
        DiffFree(&d);
        ManifestFree(&local);
        ManifestFree(&remote);
        return 0;
    } else {
        usage();
        return 1;
    }

}

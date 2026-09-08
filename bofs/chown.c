#include "bof_api.h"

void go(char *args, int args_len) {
    datap parser;
    char *path = NULL;
    int uid = -1;
    int gid = -1;

    BeaconDataParse(&parser, args, args_len);

    path = BeaconDataExtract(&parser, NULL);
    if (!path || path[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "Usage: str:/path,int:uid,int:gid\n");
        BeaconPrintf(CALLBACK_OUTPUT, "Example: str:/tmp/file,int:1000,int:1000\n");
        return;
    }

    uid = BeaconDataInt(&parser);
    gid = BeaconDataInt(&parser);

    if (uid < 0 && gid < 0) {
        BeaconPrintf(CALLBACK_ERROR, "At least one of uid/gid must be specified\n");
        return;
    }

    if (AxChown(path, (uid_t)uid, (gid_t)gid) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "chown %s: failed\n", path);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "chown %s uid=%d gid=%d: OK\n", path, uid, gid);
}

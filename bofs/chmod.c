#include "bof_api.h"

static int decimal_to_octal(int dec) {
    int octal = 0;
    int mult = 1;
    while (dec > 0) {
        int digit = dec % 10;
        if (digit > 7) return -1;
        octal += digit * mult;
        mult <<= 3;
        dec /= 10;
    }
    return octal;
}

void go(char *args, int args_len) {
    datap parser;
    char *path = NULL;
    int mode_decimal = 0;
    int mode_octal = 0;

    BeaconDataParse(&parser, args, args_len);

    mode_decimal = BeaconDataInt(&parser);
    path = BeaconDataExtract(&parser, NULL);

    if (!path || path[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "Usage: int:mode,str:/path\n");
        BeaconPrintf(CALLBACK_OUTPUT, "Example: int:755,str:/tmp/file\n");
        return;
    }

    if (mode_decimal <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid mode\n");
        return;
    }

    mode_octal = decimal_to_octal(mode_decimal);
    if (mode_octal < 0) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid octal digits: %d\n", mode_decimal);
        return;
    }

    if (AxChmod(path, (mode_t)mode_octal) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "chmod %s: failed\n", path);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "chmod %s %04o: OK\n", path, mode_octal);
}
